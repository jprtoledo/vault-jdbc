package br.com.juantoledo.vaultjdbc;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ProxySelector;
import java.net.URI;
import java.net.URL;
import java.net.URLClassLoader;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.logging.Logger;

/**
 * Finds the real JDBC driver for a {@code jdbc:vault:<subprotocol>:} URL, in this order:
 * <ol>
 *   <li>jars named in {@code vault.driverJar};</li>
 *   <li>the classpath (e.g. a driver jar configured next to vault-jdbc in the JDBC tool);</li>
 *   <li>a known driver downloaded once from Maven Central into a local cache and checked against a
 *       SHA-256 pinned in this class, so a single vault-jdbc jar is enough;</li>
 *   <li>any other registered driver that accepts the URL.</li>
 * </ol>
 */
final class DriverResolver {
    private static final Logger LOG = Logger.getLogger(DriverResolver.class.getName());
    static final String DEFAULT_REPOSITORY = "https://repo1.maven.org/maven2";
    private static final long MAX_JAR_BYTES = 64L * 1024 * 1024;
    private static final Duration TIMEOUT = Duration.ofSeconds(60);

    record Artifact(String groupId, String artifactId, String version, String sha256, String driverClass) {
        Artifact withVersion(String newVersion, String newSha256) {
            return new Artifact(groupId, artifactId, newVersion, newSha256, driverClass);
        }

        String relativePath() {
            return groupId.replace('.', '/') + "/" + artifactId + "/" + version + "/" + fileName();
        }

        String fileName() {
            return artifactId + "-" + version + ".jar";
        }
    }

    /** Drivers that can be downloaded automatically. Aurora uses the PostgreSQL/MySQL ones. */
    static final Map<String, Artifact> MANAGED = Map.of(
        "postgresql", new Artifact("org.postgresql", "postgresql", "42.7.14",
            "73914527305a40cce504b0d3d90b23caf565136912d607ae8ae7c5895512332c", "org.postgresql.Driver"),
        "mysql", new Artifact("com.mysql", "mysql-connector-j", "26.10.0",
            "cef70caf532833c9ab8f41f74773ce22c08bf503fad215c9c2ee1e9db87e759e", "com.mysql.cj.jdbc.Driver"),
        "mariadb", new Artifact("org.mariadb.jdbc", "mariadb-java-client", "4.0.0",
            "bb1211dac59ef4c54b7a8ad4755a913d36d2e81b34ca1d4cb9ffa9d5633df01f", "org.mariadb.jdbc.Driver")
    );

    /** Known driver classes that cannot be downloaded (they need other jars too). */
    private static final Map<String, String> KNOWN_CLASSES = Map.of(
        "aws-wrapper", "software.amazon.jdbc.Driver"
    );

    private final Function<String, String> env;
    private final Map<List<Path>, ClassLoader> loaders = new ConcurrentHashMap<>();
    private final Set<Path> verified = ConcurrentHashMap.newKeySet();
    private final Map<String, HttpClient> clients = new ConcurrentHashMap<>();

    DriverResolver(Function<String, String> env) {
        this.env = env;
    }

    Driver resolve(VaultUrl url) throws SQLException {
        Artifact managed = MANAGED.get(url.subprotocol);
        String className = url.option("driver");
        if (className == null) {
            className = managed != null ? managed.driverClass() : KNOWN_CLASSES.get(url.subprotocol);
        }

        String driverJar = url.option("driverJar");
        if (driverJar != null) {
            List<Path> jars = new ArrayList<>();
            for (String part : driverJar.split(",")) {
                if (!part.isBlank()) {
                    jars.add(expandHome(part.trim()));
                }
            }
            return fromJars(jars, className, url);
        }

        if (className != null) {
            Driver driver = fromClasspath(className);
            if (driver != null) {
                return driver;
            }
        }

        if (managed != null && !"false".equalsIgnoreCase(url.option("driverDownload"))) {
            Artifact artifact = managed;
            String version = url.option("driverVersion");
            if (version != null) {
                artifact = managed.withVersion(VaultConfig.validateSegment(version, "vault.driverVersion"), pinnedSha256(url));
            }
            String cacert = url.option("driverCacert");
            Path jar = ensureJar(artifact, repository(url), cacheDir(url), cacert == null ? null : expandHome(cacert));
            return fromJars(List.of(jar), className, url);
        }

        Enumeration<Driver> drivers = DriverManager.getDrivers();
        while (drivers.hasMoreElements()) {
            Driver driver = drivers.nextElement();
            if (!(driver instanceof VaultDriver) && driver.acceptsURL(url.targetUrl)) {
                return driver;
            }
        }
        throw new SQLException(className == null
            ? "No JDBC driver for subprotocol '" + url.subprotocol + "'; set vault.driverJar=/path/to/driver.jar and vault.driver=<class>"
            : "JDBC driver " + className + " not found: add its jar next to vault-jdbc or set vault.driverJar");
    }

    private static String pinnedSha256(VaultUrl url) throws SQLException {
        String value = url.option("driverSha256");
        if (value == null) {
            return null;
        }
        value = value.toLowerCase();
        if (!value.matches("[0-9a-f]{64}")) {
            throw new SQLException("vault.driverSha256 must be 64 hex characters");
        }
        return value;
    }

    Path ensureJar(Artifact artifact, String repository, Path cacheDir) throws SQLException {
        return ensureJar(artifact, repository, cacheDir, null);
    }

    /** Downloads the artifact into the cache unless a verified copy is already there. */
    Path ensureJar(Artifact artifact, String repository, Path cacheDir, Path caCert) throws SQLException {
        Path target = cacheDir.resolve(artifact.relativePath());
        synchronized (this) {
            if (verified.contains(target)) {
                return target;
            }
            String expected = artifact.sha256();
            if (Files.isRegularFile(target)) {
                if (expected == null || sha256(target).equals(expected)) {
                    verified.add(target);
                    return target;
                }
                LOG.warning(() -> "Cached " + target + " does not match its SHA-256; downloading again");
            }

            String url = repository + "/" + artifact.relativePath();
            if (expected == null) {
                expected = publishedChecksum(url, artifact, caCert);
            }
            LOG.info(() -> "Downloading JDBC driver " + url);
            try {
                Files.createDirectories(target.getParent());
                Path temp = Files.createTempFile(target.getParent(), artifact.fileName(), ".part");
                try {
                    String actual = download(url, temp, caCert);
                    if (!actual.equals(expected)) {
                        throw new SQLException("Downloaded " + artifact.fileName() + " has SHA-256 " + actual
                            + " but " + expected + " was expected; refusing to load it");
                    }
                    moveAtomically(temp, target);
                } finally {
                    Files.deleteIfExists(temp);
                }
            } catch (IOException e) {
                String hint = e instanceof javax.net.ssl.SSLHandshakeException
                    ? ". If a proxy inspects TLS (e.g. Zscaler), set vault.driverCacert=/path/to/proxy-ca.pem"
                    : ". Set vault.driverJar=/path/to/driver.jar to use a local copy";
                throw new SQLException("Could not download JDBC driver from " + url + ": " + e.getMessage() + hint, "08001", e);
            }
            verified.add(target);
            return target;
        }
    }

    /**
     * Without a pinned hash (custom vault.driverVersion), trust the checksum the repository publishes next to
     * the jar. This catches corruption but not a malicious repository; pass vault.driverSha256 to pin it.
     */
    private String publishedChecksum(String jarUrl, Artifact artifact, Path caCert) throws SQLException {
        String body = fetchText(jarUrl + ".sha256", caCert);
        if (body == null) {
            throw new SQLException("No SHA-256 published for " + artifact.fileName()
                + "; set vault.driverSha256=<sha256 of the jar> to use this version");
        }
        String checksum = body.trim().split("\\s+")[0].toLowerCase();
        if (!checksum.matches("[0-9a-f]{64}")) {
            throw new SQLException("Invalid SHA-256 published for " + artifact.fileName());
        }
        LOG.warning(() -> "Using the repository's SHA-256 for " + artifact.fileName() + "; pin it with vault.driverSha256");
        return checksum;
    }

    private String fetchText(String url, Path caCert) throws SQLException {
        try {
            HttpResponse<String> response = http(caCert).send(HttpRequest.newBuilder(URI.create(url)).timeout(TIMEOUT).GET().build(),
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return response.statusCode() == 200 ? response.body() : null;
        } catch (IOException e) {
            throw new SQLException("Could not reach " + url + ": " + e.getMessage(), "08001", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SQLException("Interrupted while downloading the JDBC driver", "08001", e);
        }
    }

    /** Streams the jar to {@code file} and returns its SHA-256. */
    private String download(String url, Path file, Path caCert) throws IOException, SQLException {
        HttpResponse<InputStream> response;
        try {
            response = http(caCert).send(HttpRequest.newBuilder(URI.create(url)).timeout(TIMEOUT).GET().build(),
                HttpResponse.BodyHandlers.ofInputStream());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SQLException("Interrupted while downloading the JDBC driver", "08001", e);
        }
        MessageDigest digest = sha256Digest();
        try (InputStream in = response.body(); OutputStream out = Files.newOutputStream(file)) {
            if (response.statusCode() != 200) {
                throw new IOException("HTTP " + response.statusCode());
            }
            byte[] buffer = new byte[64 * 1024];
            long total = 0;
            int n;
            while ((n = in.read(buffer)) != -1) {
                total += n;
                if (total > MAX_JAR_BYTES) {
                    throw new IOException("driver jar larger than " + MAX_JAR_BYTES + " bytes");
                }
                digest.update(buffer, 0, n);
                out.write(buffer, 0, n);
            }
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private Driver fromJars(List<Path> jars, String className, VaultUrl url) throws SQLException {
        for (Path jar : jars) {
            if (!Files.isRegularFile(jar)) {
                throw new SQLException("Driver jar not found: " + jar);
            }
        }
        ClassLoader loader = loaders.computeIfAbsent(List.copyOf(jars), key -> {
            URL[] urls = key.stream().map(path -> {
                try {
                    return path.toUri().toURL();
                } catch (IOException e) {
                    throw new IllegalArgumentException(e);
                }
            }).toArray(URL[]::new);
            return new URLClassLoader(urls, VaultDriver.class.getClassLoader());
        });
        if (className != null) {
            try {
                return instantiate(Class.forName(className, true, loader));
            } catch (ClassNotFoundException e) {
                throw new SQLException("JDBC driver " + className + " not found in " + jars);
            }
        }
        for (Driver driver : ServiceLoader.load(Driver.class, loader)) {
            if (!(driver instanceof VaultDriver) && driver.acceptsURL(url.targetUrl)) {
                return driver;
            }
        }
        throw new SQLException("No driver in " + jars + " accepts " + url.targetUrl + "; set vault.driver=<class>");
    }

    private static Driver fromClasspath(String className) throws SQLException {
        for (ClassLoader loader : new ClassLoader[]{VaultDriver.class.getClassLoader(), Thread.currentThread().getContextClassLoader()}) {
            if (loader == null) {
                continue;
            }
            try {
                return instantiate(Class.forName(className, true, loader));
            } catch (ClassNotFoundException ignored) {
                // try the next loader
            }
        }
        return null;
    }

    private static Driver instantiate(Class<?> type) throws SQLException {
        try {
            return (Driver) type.getDeclaredConstructor().newInstance();
        } catch (ReflectiveOperationException | ClassCastException e) {
            throw new SQLException("Could not load JDBC driver " + type.getName() + ": " + e, e);
        }
    }

    private String repository(VaultUrl url) throws SQLException {
        String repo = url.option("driverRepo");
        if (repo == null) {
            return DEFAULT_REPOSITORY;
        }
        repo = repo.replaceAll("/+$", "");
        URI uri = URI.create(repo);
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase();
        if (!scheme.equals("https") && !(scheme.equals("http") && VaultConfig.isLoopback(uri.getHost()))) {
            throw new SQLException("vault.driverRepo must use https (plain http is only allowed for localhost)");
        }
        return repo;
    }

    /** vault.driverCache, else $XDG_CACHE_HOME/vault-jdbc/drivers, else ~/.cache/vault-jdbc/drivers. */
    private Path cacheDir(VaultUrl url) {
        String custom = url.option("driverCache");
        if (custom != null) {
            return expandHome(custom);
        }
        String xdg = env.apply("XDG_CACHE_HOME");
        Path base = xdg != null && !xdg.isBlank() ? Paths.get(xdg) : expandHome("~/.cache");
        return base.resolve("vault-jdbc").resolve("drivers");
    }

    private Path expandHome(String value) {
        if (value.equals("~") || value.startsWith("~/")) {
            String home = env.apply("HOME");
            return Paths.get(home != null && !home.isBlank() ? home : System.getProperty("user.home"), value.substring(1));
        }
        return Paths.get(value);
    }

    private HttpClient http(Path caCert) throws SQLException {
        String key = caCert == null ? "" : caCert.toString();
        HttpClient existing = clients.get(key);
        if (existing != null) {
            return existing;
        }
        // Honors -Dhttps.proxyHost and friends, like the rest of the JVM.
        HttpClient.Builder builder = HttpClient.newBuilder().connectTimeout(TIMEOUT)
            .followRedirects(HttpClient.Redirect.NORMAL).proxy(ProxySelector.getDefault());
        if (caCert != null) {
            builder.sslContext(TlsTrust.withExtraCertificates(caCert));
        }
        HttpClient created = builder.build();
        HttpClient raced = clients.putIfAbsent(key, created);
        return raced == null ? created : raced;
    }

    static String sha256(Path file) throws SQLException {
        MessageDigest digest = sha256Digest();
        try (InputStream in = Files.newInputStream(file)) {
            byte[] buffer = new byte[64 * 1024];
            int n;
            while ((n = in.read(buffer)) != -1) {
                digest.update(buffer, 0, n);
            }
        } catch (IOException e) {
            throw new SQLException("Could not read " + file + ": " + e.getMessage(), e);
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private static MessageDigest sha256Digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void moveAtomically(Path source, Path target) throws IOException {
        try {
            Files.move(source, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }
}
