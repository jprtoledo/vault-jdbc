package br.com.juantoledo.vaultjdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Proxy;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverPropertyInfo;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

class VaultDriverTest {
    @TempDir
    Path home;

    private HttpServer vault;
    private final AtomicInteger vaultReads = new AtomicInteger();
    private final Set<String> validTokens = ConcurrentHashMap.newKeySet();
    private final List<String> requestedPaths = new CopyOnWriteArrayList<>();
    private volatile long leaseSeconds = 3600;
    private volatile String lastToken;
    private final AtomicLong now = new AtomicLong(1_000_000);
    private final List<Long> sleeps = new ArrayList<>();
    private final Map<String, String> env = new HashMap<>();
    private final FakeLogin login = new FakeLogin();
    private VaultDriver driver;
    private String base;

    @BeforeEach
    void setUp() throws IOException {
        vault = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        vault.createContext("/v1/", exchange -> {
            String token = exchange.getRequestHeaders().getFirst("X-Vault-Token");
            String path = exchange.getRequestURI().getPath();
            lastToken = token;
            requestedPaths.add(path);
            String body;
            int status = 200;
            if (!validTokens.contains(token)) {
                status = 403;
                body = "{\"errors\":[\"permission denied\"]}";
            } else if (path.startsWith("/v1/kv/data/")) {
                body = "{\"lease_duration\":0,\"data\":{\"data\":{\"user\":\"kvuser\",\"pass\":\"kvpass\"},\"metadata\":{}}}";
            } else if (path.contains("/static-creds/")) {
                body = "{\"lease_duration\":0,\"data\":{\"username\":\"static-user\",\"password\":\"static-pass\",\"ttl\":120}}";
            } else {
                int n = vaultReads.incrementAndGet();
                body = "{\"lease_id\":\"database/creds/app/" + n + "\",\"lease_duration\":" + leaseSeconds
                    + ",\"data\":{\"username\":\"v-app-" + n + "\\n\",\"password\":\"secret-" + n + "\"}}";
            }
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        vault.start();

        validTokens.add("file-token");
        Files.writeString(home.resolve(".vault-token"), "file-token\n");
        env.put("HOME", home.toString());
        FakeDatabaseDriver.reset();
        driver = newDriver();
        base = "jdbc:vault:fake://db.example:5432/app?sslmode=require"
            + "&vault.addr=http://127.0.0.1:" + vault.getAddress().getPort()
            + "&vault.role=app"
            + "&vault.driver=" + FakeDatabaseDriver.class.getName();
    }

    private VaultDriver newDriver() {
        return new VaultDriver(new CredentialCache(new VaultClient(login), now::get), new DriverResolver(env::get), env::get, sleeps::add);
    }

    @AfterEach
    void tearDown() {
        vault.stop(0);
    }

    // --- URL and secret path ---

    @Test
    void stripsVaultParametersAndPassesCredentials() throws SQLException {
        FakeDatabaseDriver.validPasswords.add("secret-1");
        Properties info = new Properties();
        info.setProperty("user", "ignored");
        info.setProperty("connectTimeout", "5");

        assertNotNull(driver.connect(base, info));

        assertEquals("jdbc:fake://db.example:5432/app?sslmode=require", FakeDatabaseDriver.lastUrl);
        assertEquals("v-app-1", FakeDatabaseDriver.lastProps.getProperty("user"), "trailing newline from Vault is stripped");
        assertEquals("secret-1", FakeDatabaseDriver.lastProps.getProperty("password"));
        assertEquals("5", FakeDatabaseDriver.lastProps.getProperty("connectTimeout"));
        assertEquals("file-token", lastToken);
        assertEquals(List.of("/v1/database/creds/app"), requestedPaths);
    }

    @Test
    void roleUsesCustomMount() throws SQLException {
        FakeDatabaseDriver.validPasswords.add("secret-1");
        driver.connect(base + "&vault.mount=mysql-prod", new Properties());
        assertEquals(List.of("/v1/mysql-prod/creds/app"), requestedPaths);
    }

    @Test
    void staticRolesUseStaticCredsAndTtl() throws SQLException {
        FakeDatabaseDriver.validPasswords.add("static-pass");
        driver.connect(base + "&vault.static=true", new Properties());
        assertEquals(List.of("/v1/database/static-creds/app"), requestedPaths);
        assertEquals("static-user", FakeDatabaseDriver.lastProps.getProperty("user"));

        now.addAndGet(60_000);
        driver.connect(base + "&vault.static=true", new Properties());
        assertEquals(1, requestedPaths.size(), "ttl=120s is still far from rotation");
        now.addAndGet(31_000); // 91s of 120s: inside the 30s margin
        driver.connect(base + "&vault.static=true", new Properties());
        assertEquals(2, requestedPaths.size());
    }

    @Test
    void fullPathReadsKvVersion2Secrets() throws SQLException {
        FakeDatabaseDriver.validPasswords.add("kvpass");
        String url = base.replace("vault.role=app", "vault.path=kv/data/app") + "&vault.usernameKey=user&vault.passwordKey=pass";
        driver.connect(url, new Properties());
        assertEquals("kvuser", FakeDatabaseDriver.lastProps.getProperty("user"));
    }

    @Test
    void rejectsRoleAndPathTogether() {
        SQLException error = assertThrows(SQLException.class, () -> driver.connect(base + "&vault.path=kv/data/app", new Properties()));
        assertTrue(error.getMessage().contains("not both"), error.getMessage());
    }

    @Test
    void requiresRoleOrPath() {
        SQLException error = assertThrows(SQLException.class,
            () -> driver.connect(base.replace("&vault.role=app", ""), new Properties()));
        assertTrue(error.getMessage().contains("vault.role"), error.getMessage());
    }

    @Test
    void rejectsPathTraversal() {
        assertThrows(SQLException.class, () -> driver.connect(base.replace("vault.role=app", "vault.role=../sys/raw"), new Properties()));
    }

    @Test
    void rejectsPlainHttpToRemoteVault() {
        String url = base.replaceFirst("vault.addr=[^&]+", "vault.addr=http://vault.example:8200");
        SQLException error = assertThrows(SQLException.class, () -> driver.connect(url, new Properties()));
        assertTrue(error.getMessage().contains("https"), error.getMessage());
    }

    @Test
    void vaultOptionsCanComeFromProperties() throws SQLException {
        FakeDatabaseDriver.validPasswords.add("secret-1");
        Properties info = new Properties();
        info.setProperty("vault.role", "app");
        driver.connect(base.replace("&vault.role=app", ""), info);
        assertFalse(FakeDatabaseDriver.lastProps.containsKey("vault.role"));
        assertEquals("v-app-1", FakeDatabaseDriver.lastProps.getProperty("user"));
    }

    @Test
    void ignoresOtherUrls() throws SQLException {
        assertFalse(driver.acceptsURL("jdbc:postgresql://db/app"));
        assertNull(driver.connect("jdbc:postgresql://db/app", new Properties()));
    }

    // --- credential lifecycle ---

    @Test
    void sharesOneCredentialAcrossConnections() throws SQLException {
        FakeDatabaseDriver.validPasswords.add("secret-1");
        driver.connect(base, new Properties());
        driver.connect(base, new Properties());
        driver.connect(base, new Properties());
        assertEquals(1, vaultReads.get());
    }

    @Test
    void refetchesWhenLeaseIsAboutToExpire() throws SQLException {
        leaseSeconds = 100;
        FakeDatabaseDriver.validPasswords.addAll(Set.of("secret-1", "secret-2"));
        driver.connect(base, new Properties());
        now.addAndGet(60_000);
        driver.connect(base, new Properties());
        assertEquals(1, vaultReads.get());
        now.addAndGet(15_000); // 75s of 100s elapsed: inside the 30s refresh margin
        driver.connect(base, new Properties());
        assertEquals(2, vaultReads.get());
        assertEquals("v-app-2", FakeDatabaseDriver.lastProps.getProperty("user"));
    }

    @Test
    void fetchesNewCredentialWhenDatabaseRejectsCachedOne() throws SQLException {
        FakeDatabaseDriver.validPasswords.add("secret-1");
        driver.connect(base, new Properties());
        FakeDatabaseDriver.validPasswords.clear();
        FakeDatabaseDriver.validPasswords.add("secret-2");
        now.addAndGet(60_000);

        driver.connect(base, new Properties());

        assertEquals(2, vaultReads.get());
        assertEquals("secret-2", FakeDatabaseDriver.lastProps.getProperty("password"));
        assertTrue(sleeps.isEmpty());
    }

    @Test
    void waitsInsteadOfRefetchingWhenFreshCredentialIsRejected() throws SQLException {
        FakeDatabaseDriver.failuresBeforeAccepting.set(1);
        FakeDatabaseDriver.validPasswords.add("secret-1");

        driver.connect(base, new Properties());

        assertEquals(1, vaultReads.get());
        assertEquals(List.of(1_000L), sleeps);
    }

    @Test
    void refetchesWhenFreshCredentialKeepsFailing() throws SQLException {
        FakeDatabaseDriver.validPasswords.add("secret-1");
        driver.connect(base, new Properties());
        FakeDatabaseDriver.validPasswords.clear();
        FakeDatabaseDriver.validPasswords.add("secret-2");

        driver.connect(base, new Properties());

        assertEquals(2, vaultReads.get());
        assertEquals(List.of(1_000L), sleeps);
        assertEquals("secret-2", FakeDatabaseDriver.lastProps.getProperty("password"));
    }

    @Test
    void givesUpAfterConfiguredRetries() {
        FakeDatabaseDriver.validPasswords.add("never-issued");
        SQLException error = assertThrows(SQLException.class, () -> driver.connect(base + "&vault.authRetries=1", new Properties()));
        assertEquals("28P01", error.getSQLState());
        assertEquals(2, FakeDatabaseDriver.attempts.get());
    }

    @Test
    void doesNotRetryNonAuthFailures() {
        FakeDatabaseDriver.networkDown = true;
        assertThrows(SQLException.class, () -> driver.connect(base, new Properties()));
        assertEquals(1, FakeDatabaseDriver.attempts.get());
    }

    @Test
    void authFailureDetectionCoversPostgresAndMysql() {
        assertTrue(VaultDriver.isAuthFailure(new SQLException("pg", "28P01")));
        assertTrue(VaultDriver.isAuthFailure(new SQLException("mysql", "28000", 1045)));
        assertTrue(VaultDriver.isAuthFailure(new SQLException("wrapped", "08001", new SQLException("inner", null, 1045))));
        assertFalse(VaultDriver.isAuthFailure(new SQLException("down", "08001")));
    }

    // --- Vault token and login ---

    @Test
    void vaultTokenEnvironmentVariableWinsOverFile() throws SQLException {
        validTokens.add("env-token");
        env.put("VAULT_TOKEN", "env-token");
        FakeDatabaseDriver.validPasswords.add("secret-1");
        driver.connect(base, new Properties());
        assertEquals("env-token", lastToken);
    }

    @Test
    void staleEnvironmentTokenFallsBackToFile() throws SQLException {
        env.put("VAULT_TOKEN", "stale-env-token");
        FakeDatabaseDriver.validPasswords.add("secret-1");
        driver.connect(base, new Properties());
        assertEquals("file-token", lastToken);
        assertEquals(0, login.calls.get());
    }

    @Test
    void defaultTokenMethodNeverAutoLogsIn() {
        validTokens.clear();
        SQLException error = assertThrows(VaultClient.VaultAuthException.class, () -> driver.connect(base, new Properties()));
        assertTrue(error.getMessage().contains("run: vault login"), error.getMessage());
        assertTrue(error.getMessage().contains("permission denied"), error.getMessage());
        assertEquals(0, login.calls.get());
        assertEquals(0, FakeDatabaseDriver.attempts.get());
    }

    @Test
    void expiredTokenTriggersLoginWithMethodAndPath() throws SQLException {
        validTokens.clear();
        validTokens.add("fresh-login-token");
        login.nextToken = "fresh-login-token";
        FakeDatabaseDriver.validPasswords.add("secret-1");

        driver.connect(base + "&vault.method=oidc&vault.authPath=okta_oidc", new Properties());

        assertEquals(1, login.calls.get());
        assertEquals("oidc", login.lastConfig.method);
        assertEquals("okta_oidc", login.lastConfig.authPath);
        assertEquals("vault login -method=oidc -path=okta_oidc", login.lastConfig.loginCommand());
        assertEquals("fresh-login-token", lastToken);
    }

    @Test
    void missingTokenFileTriggersLogin() throws SQLException, IOException {
        Files.delete(home.resolve(".vault-token"));
        validTokens.add("fresh-login-token");
        login.nextToken = "fresh-login-token";
        FakeDatabaseDriver.validPasswords.add("secret-1");

        driver.connect(base + "&vault.method=oidc", new Properties());

        assertEquals(1, login.calls.get());
        assertEquals("oidc", login.lastConfig.authPath, "auth path defaults to the method name");
    }

    @Test
    void tokenFromLoginIsReusedUntilRejected() throws SQLException {
        validTokens.clear();
        validTokens.add("fresh-login-token");
        login.nextToken = "fresh-login-token";
        FakeDatabaseDriver.validPasswords.addAll(Set.of("secret-1", "secret-2"));
        String url = base + "&vault.method=oidc";

        driver.connect(url, new Properties());
        driver.connect(url.replace("vault.role=app", "vault.role=other"), new Properties());

        assertEquals(1, login.calls.get());
        assertEquals("fresh-login-token", lastToken);
    }

    @Test
    void newerTokenFileIsTriedBeforeLoggingInAgain() throws SQLException, IOException {
        validTokens.clear();
        validTokens.add("fresh-login-token");
        login.nextToken = "fresh-login-token";
        FakeDatabaseDriver.validPasswords.addAll(Set.of("secret-1", "secret-2"));
        String url = base + "&vault.method=oidc";
        driver.connect(url, new Properties());

        // The login token expires; the user logs in again from a terminal.
        validTokens.clear();
        validTokens.add("terminal-token");
        Files.writeString(home.resolve(".vault-token"), "terminal-token");
        driver.connect(url.replace("vault.role=app", "vault.role=other"), new Properties());

        assertEquals(1, login.calls.get());
        assertEquals("terminal-token", lastToken);
    }

    @Test
    void autoLoginCanBeDisabled() {
        validTokens.clear();
        assertThrows(VaultClient.VaultAuthException.class,
            () -> driver.connect(base + "&vault.method=oidc&vault.autoLogin=false", new Properties()));
        assertEquals(0, login.calls.get());
    }

    @Test
    void concurrentConnectionsLogInOnce() throws Exception {
        validTokens.clear();
        validTokens.add("fresh-login-token");
        login.nextToken = "fresh-login-token";
        login.delayMillis = 200;
        FakeDatabaseDriver.validPasswords.addAll(Set.of("secret-1", "secret-2", "secret-3", "secret-4"));
        String url = base + "&vault.method=oidc";

        ExecutorService pool = Executors.newFixedThreadPool(4);
        try {
            List<Future<Connection>> futures = new ArrayList<>();
            for (int i = 0; i < 4; i++) {
                String role = "role" + i; // distinct paths so the credential cache does not serialize them
                futures.add(pool.submit(() -> driver.connect(url.replace("vault.role=app", "vault.role=" + role), new Properties())));
            }
            for (Future<Connection> future : futures) {
                future.get();
            }
        } finally {
            pool.shutdownNow();
        }
        assertEquals(1, login.calls.get());
    }

    @Test
    void loginCommandMasksSensitiveArguments() throws SQLException {
        VaultConfig config = VaultConfig.from(VaultUrl.parse(base + "&vault.method=userpass&vault.authPath=corp"
            + "&vault.loginArgs=username%3Dalice,password%3Ds3cr3t,passcode%3D123", new Properties()), env::get);
        assertEquals("vault login -method=userpass -path=corp username=alice password=*** passcode=***", config.loginCommand());
    }

    @Test
    void loginArgsAreValidated() {
        assertThrows(SQLException.class, () -> driver.connect(base + "&vault.method=oidc&vault.loginArgs=-no-store", new Properties()));
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void cliLoginPassesFlagsAndEnvironmentAndReadsToken() throws Exception {
        Path argsFile = home.resolve("args.txt");
        Path cli = home.resolve("vault");
        Files.writeString(cli, "#!/bin/sh\n"
            + "printf '%s\\n' \"$@\" > '" + argsFile + "'\n"
            + "printf 'VAULT_ADDR=%s\\nVAULT_TOKEN=%s\\n' \"$VAULT_ADDR\" \"${VAULT_TOKEN:-unset}\" >> '" + argsFile + "'\n"
            + "echo 'Complete the login via your OIDC provider.' >&2\n"
            + "echo '{\"auth\":{\"client_token\":\"cli-token\"}}'\n");
        Files.setPosixFilePermissions(cli, PosixFilePermissions.fromString("rwx------"));

        VaultConfig config = VaultConfig.from(VaultUrl.parse(base + "&vault.method=oidc&vault.authPath=okta_oidc"
            + "&vault.loginArgs=role%3Ddba,skip_browser%3Dfalse&vault.cli=" + cli, new Properties()), env::get);

        assertEquals("cli-token", new VaultLogin().login(config));
        assertEquals(List.of("login", "-format=json", "-method=oidc", "-path=okta_oidc", "role=dba", "skip_browser=false",
            "VAULT_ADDR=" + config.addr, "VAULT_TOKEN=unset"), Files.readAllLines(argsFile));
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void cliLoginFailureReportsLastStderrLine() throws Exception {
        Path cli = home.resolve("vault");
        Files.writeString(cli, "#!/bin/sh\necho 'Error authenticating: user cancelled' >&2\nexit 2\n");
        Files.setPosixFilePermissions(cli, PosixFilePermissions.fromString("rwx------"));
        VaultConfig config = VaultConfig.from(VaultUrl.parse(base + "&vault.method=oidc&vault.cli=" + cli, new Properties()), env::get);

        SQLException error = assertThrows(SQLException.class, () -> new VaultLogin().login(config));
        assertTrue(error.getMessage().contains("user cancelled"), error.getMessage());
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void cliLoginTimesOut() throws Exception {
        Path cli = home.resolve("vault");
        Files.writeString(cli, "#!/bin/sh\nexec sleep 30\n");
        Files.setPosixFilePermissions(cli, PosixFilePermissions.fromString("rwx------"));
        VaultConfig config = VaultConfig.from(VaultUrl.parse(base + "&vault.method=oidc&vault.loginTimeout=1&vault.cli=" + cli,
            new Properties()), env::get);

        SQLException error = assertThrows(SQLException.class, () -> new VaultLogin().login(config));
        assertTrue(error.getMessage().contains("did not finish within 1s"), error.getMessage());
    }

    private static final class FakeLogin extends VaultLogin {
        final AtomicInteger calls = new AtomicInteger();
        volatile String nextToken;
        volatile VaultConfig lastConfig;
        volatile long delayMillis;

        @Override
        String login(VaultConfig config) throws SQLException {
            calls.incrementAndGet();
            lastConfig = config;
            try {
                Thread.sleep(delayMillis);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            if (nextToken == null) {
                throw new SQLException("login failed", "28000");
            }
            return nextToken;
        }
    }

    /** Stands in for the real PostgreSQL/MySQL driver. */
    public static final class FakeDatabaseDriver implements Driver {
        static final Set<String> validPasswords = ConcurrentHashMap.newKeySet();
        static final AtomicInteger attempts = new AtomicInteger();
        static final AtomicInteger failuresBeforeAccepting = new AtomicInteger();
        static volatile boolean networkDown;
        static volatile String lastUrl;
        static volatile Properties lastProps;

        static void reset() {
            validPasswords.clear();
            attempts.set(0);
            failuresBeforeAccepting.set(0);
            networkDown = false;
            lastUrl = null;
            lastProps = null;
        }

        @Override
        public Connection connect(String url, Properties info) throws SQLException {
            attempts.incrementAndGet();
            lastUrl = url;
            lastProps = (Properties) info.clone();
            if (networkDown) {
                throw new SQLException("Connection refused", "08001");
            }
            if (failuresBeforeAccepting.getAndUpdate(n -> Math.max(0, n - 1)) > 0
                || !validPasswords.contains(info.getProperty("password"))) {
                throw new SQLException("password authentication failed", "28P01");
            }
            return (Connection) Proxy.newProxyInstance(Connection.class.getClassLoader(), new Class<?>[]{Connection.class},
                (proxy, method, args) -> null);
        }

        @Override
        public boolean acceptsURL(String url) {
            return url.startsWith("jdbc:fake:");
        }

        @Override
        public DriverPropertyInfo[] getPropertyInfo(String url, Properties info) {
            return new DriverPropertyInfo[0];
        }

        @Override
        public int getMajorVersion() {
            return 1;
        }

        @Override
        public int getMinorVersion() {
            return 0;
        }

        @Override
        public boolean jdbcCompliant() {
            return false;
        }

        @Override
        public Logger getParentLogger() {
            return Logger.getGlobal();
        }
    }
}
