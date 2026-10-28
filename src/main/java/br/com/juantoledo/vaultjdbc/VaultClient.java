package br.com.juantoledo.vaultjdbc;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.sql.SQLException;
import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * Reads a credential from Vault over HTTPS. Tokens are tried in this order: the one that last worked for this
 * server in this process, VAULT_TOKEN, the per-server token file (~/.vault-tokens/...), and the shared
 * ~/.vault-token left by {@code vault login}. If Vault rejects all of them and auto-login is allowed,
 * {@code vault login -no-store} is run and its token saved to the per-server file, so logging in to one
 * server never overwrites the token of another.
 */
class VaultClient {
    private static final Logger LOG = Logger.getLogger(VaultClient.class.getName());
    private static final Duration TIMEOUT = Duration.ofSeconds(15);

    private final VaultLogin login;
    private final Map<String, HttpClient> clients = new ConcurrentHashMap<>();
    /** Token that last worked, per Vault server. */
    private final Map<String, String> knownTokens = new ConcurrentHashMap<>();
    private final Map<String, Object> loginLocks = new ConcurrentHashMap<>();

    VaultClient(VaultLogin login) {
        this.login = login;
    }

    Credential read(VaultConfig config) throws SQLException {
        String known = knownTokens.get(config.serverKey());
        VaultAuthException rejected = null;
        for (String token : candidateTokens(config, known)) {
            try {
                Credential credential = fetch(config, token);
                knownTokens.put(config.serverKey(), token);
                return credential;
            } catch (VaultAuthException e) {
                if (rejected == null) {
                    rejected = e;
                }
            }
        }
        if (rejected == null) {
            rejected = new VaultAuthException("No Vault token for " + config.addr + " (looked in VAULT_TOKEN, "
                + config.serverTokenFile() + " and " + config.tokenFile + "); run: " + config.loginCommand());
        }
        if (!config.autoLogin) {
            throw rejected;
        }
        return fetch(config, loginOnce(config, known));
    }

    private static Set<String> candidateTokens(VaultConfig config, String known) throws SQLException {
        Set<String> tokens = new LinkedHashSet<>();
        addIfPresent(tokens, known);
        addIfPresent(tokens, config.envToken);
        addIfPresent(tokens, readTokenFile(config.serverTokenFile()));
        addIfPresent(tokens, readTokenFile(config.tokenFile));
        return tokens;
    }

    private static void addIfPresent(Set<String> tokens, String token) {
        if (token != null) {
            tokens.add(token);
        }
    }

    /** One login at a time per server; a caller that waited reuses the token the previous login produced. */
    private String loginOnce(VaultConfig config, String rejectedToken) throws SQLException {
        Object lock = loginLocks.computeIfAbsent(config.serverKey(), key -> new Object());
        synchronized (lock) {
            String current = knownTokens.get(config.serverKey());
            if (current != null && !current.equals(rejectedToken)) {
                return current;
            }
            String token = login.login(config);
            knownTokens.put(config.serverKey(), token);
            try {
                writeTokenFile(config.serverTokenFile(), token);
            } catch (IOException e) {
                // The token still works for this process; only reuse after a restart is lost.
                LOG.warning(() -> "Could not save Vault token to " + config.serverTokenFile() + ": " + e.getMessage());
            }
            return token;
        }
    }

    /** Writes the token with owner-only permissions, atomically, like the vault CLI does for ~/.vault-token. */
    static void writeTokenFile(Path file, String token) throws IOException {
        Path dir = file.toAbsolutePath().getParent();
        boolean posix = dir.getFileSystem().supportedFileAttributeViews().contains("posix");
        if (!Files.isDirectory(dir)) {
            if (posix) {
                Files.createDirectories(dir, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
            } else {
                Files.createDirectories(dir);
            }
        }
        Path temp = posix
            ? Files.createTempFile(dir, ".token", ".tmp", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
            : Files.createTempFile(dir, ".token", ".tmp");
        try {
            Files.writeString(temp, token, StandardCharsets.UTF_8);
            try {
                Files.move(temp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    private Credential fetch(VaultConfig config, String token) throws SQLException {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(config.addr + "/v1/" + config.secretPath))
            .timeout(TIMEOUT)
            .header("X-Vault-Token", token)
            .header("X-Vault-Request", "true")
            .GET();
        if (config.namespace != null) {
            request.header("X-Vault-Namespace", config.namespace);
        }

        HttpResponse<String> response;
        try {
            response = client(config).send(request.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new SQLException("Could not reach Vault at " + config.addr + ": " + e.getMessage(), "08001", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SQLException("Interrupted while reading credentials from Vault", "08001", e);
        }

        int status = response.statusCode();
        if (status == 401 || status == 403) {
            throw new VaultAuthException("Vault rejected the token (HTTP " + status + ") for " + config.secretPath
                + ". The login probably expired, or the token lacks access to this path; run: "
                + config.loginCommand() + vaultErrors(response.body()));
        }
        if (status == 404) {
            throw new SQLException("Vault path not found: " + config.secretPath + vaultErrors(response.body()));
        }
        if (status != 200) {
            throw new SQLException("Vault returned HTTP " + status + " for " + config.secretPath + vaultErrors(response.body()), "08001");
        }
        return toCredential(config, response.body());
    }

    static Credential toCredential(VaultConfig config, String body) throws SQLException {
        Map<String, Object> root = asMap(parse(body));
        Map<String, Object> data = asMap(root == null ? null : root.get("data"));
        // KV v2 nests the secret under data.data; database creds and KV v1 put it directly under data.
        Map<String, Object> nested = asMap(data == null ? null : data.get("data"));
        if (nested != null && data.containsKey("metadata")) {
            data = nested;
        }
        Object username = data == null ? null : data.get(config.usernameKey);
        Object password = data == null ? null : data.get(config.passwordKey);
        if (!(username instanceof String) || !(password instanceof String)) {
            throw new SQLException("Vault secret at " + config.secretPath + " has no '" + config.usernameKey + "'/'"
                + config.passwordKey + "' fields (set vault.usernameKey / vault.passwordKey)");
        }
        long leaseSeconds = number(root.get("lease_duration"));
        if (leaseSeconds == 0) {
            // Static roles have no lease; their data.ttl is the time until the next password rotation.
            leaseSeconds = number(data.get("ttl"));
        }
        Object leaseId = root.get("lease_id");
        // Some username_template configs leave a trailing newline that is not part of the database user.
        return new Credential(((String) username).strip(), (String) password,
            leaseId instanceof String ? (String) leaseId : "", leaseSeconds, 0L);
    }

    private static String readTokenFile(Path file) throws SQLException {
        try {
            String token = Files.readString(file, StandardCharsets.UTF_8).trim();
            return token.isEmpty() ? null : token;
        } catch (NoSuchFileException e) {
            return null;
        } catch (IOException e) {
            throw new SQLException("Could not read Vault token file " + file + ": " + e.getMessage(), e);
        }
    }

    private HttpClient client(VaultConfig config) throws SQLException {
        String key = Objects.toString(config.caCert, "");
        HttpClient existing = clients.get(key);
        if (existing != null) {
            return existing;
        }
        HttpClient.Builder builder = HttpClient.newBuilder().connectTimeout(TIMEOUT);
        if (config.caCert != null) {
            builder.sslContext(TlsTrust.withExtraCertificates(config.caCert));
        }
        HttpClient created = builder.build();
        HttpClient raced = clients.putIfAbsent(key, created);
        return raced == null ? created : raced;
    }

    /** Vault's "errors" array never contains secrets; the rest of the body might. */
    private static String vaultErrors(String body) {
        try {
            Map<String, Object> root = asMap(Json.parse(body));
            Object errors = root == null ? null : root.get("errors");
            if (errors instanceof List && !((List<?>) errors).isEmpty()) {
                return " (" + ((List<?>) errors).stream().map(e -> String.valueOf(e).strip()).collect(Collectors.joining("; ")) + ")";
            }
        } catch (IllegalArgumentException ignored) {
            // Not JSON; say nothing rather than echo the body.
        }
        return "";
    }

    private static Object parse(String body) throws SQLException {
        try {
            return Json.parse(body);
        } catch (IllegalArgumentException e) {
            throw new SQLException("Vault returned an invalid JSON response: " + e.getMessage());
        }
    }

    private static long number(Object value) {
        return value instanceof Number ? ((Number) value).longValue() : 0L;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object value) {
        return value instanceof Map ? (Map<String, Object>) value : null;
    }

    /** Thrown when the Vault login itself is missing, expired or not allowed: retrying the database cannot help. */
    static final class VaultAuthException extends SQLException {
        VaultAuthException(String message) {
            super(message, "28000");
        }
    }

    record Credential(String username, String password, String leaseId, long leaseSeconds, long fetchedAtMillis) {
        Credential fetchedAt(long millis) {
            return new Credential(username, password, leaseId, leaseSeconds, millis);
        }

        /** Never print the password. */
        @Override
        public String toString() {
            return "Credential[lease=" + leaseSeconds + "s]";
        }
    }
}
