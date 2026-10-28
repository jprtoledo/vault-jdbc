package br.com.juantoledo.vaultjdbc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import br.com.juantoledo.vaultjdbc.DriverResolver.Artifact;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.sql.Driver;
import java.sql.SQLException;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class DriverResolverTest {
    @TempDir
    Path dir;

    private HttpServer repo;
    private final Map<String, byte[]> files = new ConcurrentHashMap<>();
    private final List<String> requests = new CopyOnWriteArrayList<>();
    private String repoUrl;
    private DriverResolver resolver;
    private final byte[] jar = "pretend this is a jar".getBytes(StandardCharsets.UTF_8);
    private final Artifact artifact = new Artifact("com.example", "driver", "1.0", sha256(jar), "com.example.Driver");

    @BeforeEach
    void setUp() throws IOException {
        repo = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        repo.createContext("/", exchange -> {
            String path = exchange.getRequestURI().getPath();
            requests.add(path);
            byte[] body = files.get(path);
            exchange.sendResponseHeaders(body == null ? 404 : 200, body == null ? -1 : body.length);
            if (body != null) {
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(body);
                }
            }
            exchange.close();
        });
        repo.start();
        repoUrl = "http://127.0.0.1:" + repo.getAddress().getPort();
        files.put("/com/example/driver/1.0/driver-1.0.jar", jar);
        resolver = new DriverResolver(Map.of("HOME", dir.toString())::get);
    }

    @AfterEach
    void tearDown() {
        repo.stop(0);
    }

    @Test
    void downloadsVerifiesAndCaches() throws SQLException, IOException {
        Path cache = dir.resolve("cache");
        Path first = resolver.ensureJar(artifact, repoUrl, cache);

        assertEquals(cache.resolve("com/example/driver/1.0/driver-1.0.jar"), first);
        assertArrayEquals(jar, Files.readAllBytes(first));
        try (var listing = Files.list(first.getParent())) {
            assertEquals(1, listing.count(), "no partial files left behind");
        }

        // Same process: no new request. New process (new resolver): verifies the file, still no download.
        resolver.ensureJar(artifact, repoUrl, cache);
        new DriverResolver(Map.of("HOME", dir.toString())::get).ensureJar(artifact, repoUrl, cache);
        assertEquals(1, requests.size());
    }

    @Test
    void refusesJarWithWrongChecksum() throws IOException {
        Path cache = dir.resolve("cache");
        Artifact tampered = new Artifact("com.example", "driver", "1.0", "0".repeat(64), "com.example.Driver");

        SQLException error = assertThrows(SQLException.class, () -> resolver.ensureJar(tampered, repoUrl, cache));

        assertTrue(error.getMessage().contains("refusing to load"), error.getMessage());
        Path versionDir = cache.resolve("com/example/driver/1.0");
        try (var listing = Files.list(versionDir)) {
            assertEquals(0, listing.count(), "nothing is kept after a checksum mismatch");
        }
    }

    @Test
    void replacesCorruptedCachedJar() throws SQLException, IOException {
        Path cache = dir.resolve("cache");
        Path target = cache.resolve("com/example/driver/1.0/driver-1.0.jar");
        Files.createDirectories(target.getParent());
        Files.writeString(target, "corrupted");

        resolver.ensureJar(artifact, repoUrl, cache);

        assertArrayEquals(jar, Files.readAllBytes(target));
        assertEquals(1, requests.size());
    }

    @Test
    void unpinnedVersionUsesPublishedSha256() throws SQLException {
        files.put("/com/example/driver/1.0/driver-1.0.jar.sha256", (sha256(jar) + "  driver-1.0.jar\n").getBytes(StandardCharsets.UTF_8));
        Artifact unpinned = artifact.withVersion("1.0", null);

        resolver.ensureJar(unpinned, repoUrl, dir.resolve("cache"));

        assertEquals(List.of("/com/example/driver/1.0/driver-1.0.jar.sha256", "/com/example/driver/1.0/driver-1.0.jar"), requests);
    }

    @Test
    void unpinnedVersionWithoutPublishedSha256IsRefused() {
        Artifact unpinned = artifact.withVersion("1.0", null);
        SQLException error = assertThrows(SQLException.class, () -> resolver.ensureJar(unpinned, repoUrl, dir.resolve("cache")));
        assertTrue(error.getMessage().contains("vault.driverSha256"), error.getMessage());
    }

    @Test
    void missingJarSuggestsLocalCopy() {
        Artifact missing = new Artifact("com.example", "nope", "1.0", "0".repeat(64), "com.example.Driver");
        SQLException error = assertThrows(SQLException.class, () -> resolver.ensureJar(missing, repoUrl, dir.resolve("cache")));
        assertTrue(error.getMessage().contains("vault.driverJar"), error.getMessage());
    }

    @Test
    void classpathDriverIsUsedWithoutDownloading() throws SQLException {
        String url = "jdbc:vault:mysql://db/app?vault.driver=" + VaultDriverTest.FakeDatabaseDriver.class.getName()
            + "&vault.driverRepo=" + repoUrl;
        Driver driver = resolver.resolve(VaultUrl.parse(url, new Properties()));
        assertInstanceOf(VaultDriverTest.FakeDatabaseDriver.class, driver);
        assertTrue(requests.isEmpty());
    }

    @Test
    void driverJarIsLoadedExplicitly() throws Exception {
        Path emptyJar = dir.resolve("extra.jar");
        try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(emptyJar))) {
            out.flush();
        }
        String url = "jdbc:vault:fake://db/app?vault.driver=" + VaultDriverTest.FakeDatabaseDriver.class.getName()
            + "&vault.driverJar=" + emptyJar;
        assertInstanceOf(Driver.class, resolver.resolve(VaultUrl.parse(url, new Properties())));

        SQLException error = assertThrows(SQLException.class,
            () -> resolver.resolve(VaultUrl.parse("jdbc:vault:fake://db/app?vault.driverJar=" + dir.resolve("missing.jar"), new Properties())));
        assertTrue(error.getMessage().contains("not found"), error.getMessage());
    }

    @Test
    void downloadCanBeDisabled() {
        String url = "jdbc:vault:mysql://db/app?vault.driverDownload=false&vault.driverRepo=" + repoUrl;
        SQLException error = assertThrows(SQLException.class, () -> resolver.resolve(VaultUrl.parse(url, new Properties())));
        assertTrue(error.getMessage().contains("com.mysql.cj.jdbc.Driver"), error.getMessage());
        assertTrue(requests.isEmpty());
    }

    @Test
    void rejectsPlainHttpRepository() {
        String url = "jdbc:vault:mysql://db/app?vault.driverRepo=http://repo.example.com/maven2";
        SQLException error = assertThrows(SQLException.class, () -> resolver.resolve(VaultUrl.parse(url, new Properties())));
        assertTrue(error.getMessage().contains("https"), error.getMessage());
    }

    @Test
    void rejectsMalformedPinnedChecksumAndVersion() {
        assertThrows(SQLException.class, () -> resolver.resolve(VaultUrl.parse(
            "jdbc:vault:mysql://db/app?vault.driverVersion=9.0&vault.driverSha256=abc", new Properties())));
        assertThrows(SQLException.class, () -> resolver.resolve(VaultUrl.parse(
            "jdbc:vault:mysql://db/app?vault.driverVersion=../../evil", new Properties())));
    }

    @Test
    void managedDriversArePinned() {
        for (Artifact managed : DriverResolver.MANAGED.values()) {
            assertTrue(managed.sha256().matches("[0-9a-f]{64}"), managed.artifactId());
            assertFalse(managed.version().isBlank(), managed.artifactId());
        }
    }

    private static String sha256(byte[] data) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
