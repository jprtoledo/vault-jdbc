package br.com.juantoledo.vaultjdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import br.com.juantoledo.vaultjdbc.VaultDriverTest.FakeDatabaseDriver;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermissions;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

/** Two Vault servers, each accepting only its own token. */
class MultiServerTokenTest {
    @TempDir
    Path home;

    private FakeVault vaultA;
    private FakeVault vaultB;
    private final Map<String, String> env = new HashMap<>();
    private final AtomicInteger logins = new AtomicInteger();
    private final List<String> loginServers = new CopyOnWriteArrayList<>();

    @BeforeEach
    void setUp() throws IOException {
        vaultA = new FakeVault("token-A", "pass-A");
        vaultB = new FakeVault("token-B", "pass-B");
        env.put("HOME", home.toString());
        FakeDatabaseDriver.reset();
        FakeDatabaseDriver.validPasswords.add("pass-A");
        FakeDatabaseDriver.validPasswords.add("pass-B");
    }

    @AfterEach
    void tearDown() {
        vaultA.server.stop(0);
        vaultB.server.stop(0);
    }

    private VaultDriver newDriver() {
        // Simulates `vault login` against whichever server the config points at.
        VaultLogin login = new VaultLogin() {
            @Override
            String login(VaultConfig config) {
                logins.incrementAndGet();
                loginServers.add(config.addr.toString());
                return config.addr.toString().equals(vaultA.addr) ? "token-A" : "token-B";
            }
        };
        return new VaultDriver(new CredentialCache(new VaultClient(login), System::currentTimeMillis),
            new DriverResolver(env::get), env::get, millis -> { });
    }

    private String url(FakeVault vault) {
        return "jdbc:vault:fake://db/app?vault.addr=" + vault.addr + "&vault.role=app&vault.method=oidc"
            + "&vault.driver=" + FakeDatabaseDriver.class.getName();
    }

    @Test
    void loggingInToTwoServersKeepsBothTokens() throws SQLException, IOException {
        VaultDriver driver = newDriver();
        driver.connect(url(vaultA), new Properties());
        driver.connect(url(vaultB), new Properties());
        assertEquals(List.of(vaultA.addr, vaultB.addr), loginServers);

        assertEquals("token-A", Files.readString(tokenFile(vaultA)));
        assertEquals("token-B", Files.readString(tokenFile(vaultB)));
        assertFalse(Files.exists(home.resolve(".vault-token")), "the shared CLI token file is left alone");

        // After a restart both servers still work without logging in again.
        VaultDriver restarted = newDriver();
        restarted.connect(url(vaultA), new Properties());
        restarted.connect(url(vaultB), new Properties());
        assertEquals(2, logins.get());
    }

    @Test
    void sharedTokenOfAnotherServerDoesNotGetInTheWay() throws Exception {
        VaultClient.writeTokenFile(tokenFile(vaultA), "token-A");
        Files.writeString(home.resolve(".vault-token"), "token-B"); // last terminal login was to B

        newDriver().connect(url(vaultA), new Properties());
        newDriver().connect(url(vaultB), new Properties());

        assertEquals(0, logins.get());
        assertEquals(0, vaultA.rejected.get(), "A's own token file is tried before the shared one");
    }

    @Test
    void sharedTokenFileStillWorksForASingleServer() throws Exception {
        Files.writeString(home.resolve(".vault-token"), "token-B");
        newDriver().connect(url(vaultB), new Properties());
        assertEquals(0, logins.get());
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void tokenFilesAreOwnerOnly() throws Exception {
        newDriver().connect(url(vaultA), new Properties());
        Path file = tokenFile(vaultA);
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(file)));
        assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(file.getParent())));
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void cliTokenHelperUsesTheSameFiles() throws Exception {
        // Terminal: `VAULT_ADDR=<A>/ vault login` stores through the helper (note the trailing slash).
        helper("store", vaultA.addr + "/", null, "token-A");
        newDriver().connect(url(vaultA), new Properties());
        assertEquals(0, logins.get());

        // Driver logs in to B; the terminal then reads B's token through the helper.
        newDriver().connect(url(vaultB), new Properties());
        assertEquals("token-B", helper("get", vaultB.addr, null, null));

        helper("erase", vaultB.addr, null, null);
        assertFalse(Files.exists(tokenFile(vaultB)));
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void helperAndDriverAgreeOnNamespacedFileNames() throws Exception {
        helper("store", vaultA.addr, "team/a b", "token-ns");
        VaultConfig config = VaultConfig.from(VaultUrl.parse(url(vaultA) + "&vault.namespace=team/a%20b", new Properties()), env::get);
        assertEquals("token-ns", Files.readString(config.serverTokenFile()));
    }

    private Path tokenFile(FakeVault vault) throws SQLException {
        return VaultConfig.from(VaultUrl.parse(url(vault), new Properties()), env::get).serverTokenFile();
    }

    private String helper(String op, String addr, String namespace, String stdin) throws Exception {
        Path script = Paths.get("contrib/vault-token-helper.sh").toAbsolutePath();
        ProcessBuilder builder = new ProcessBuilder("sh", script.toString(), op);
        builder.environment().put("HOME", home.toString());
        builder.environment().remove("VAULT_JDBC_TOKEN_DIR");
        builder.environment().put("VAULT_ADDR", addr);
        if (namespace != null) {
            builder.environment().put("VAULT_NAMESPACE", namespace);
        } else {
            builder.environment().remove("VAULT_NAMESPACE");
        }
        Process process = builder.start();
        try (OutputStream in = process.getOutputStream()) {
            if (stdin != null) {
                in.write(stdin.getBytes(StandardCharsets.UTF_8));
            }
        }
        String out = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertEquals(0, process.waitFor(), new String(process.getErrorStream().readAllBytes(), StandardCharsets.UTF_8));
        return out;
    }

    private static final class FakeVault {
        final HttpServer server;
        final String addr;
        final AtomicInteger rejected = new AtomicInteger();

        FakeVault(String validToken, String password) throws IOException {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/v1/", exchange -> {
                boolean ok = validToken.equals(exchange.getRequestHeaders().getFirst("X-Vault-Token"));
                if (!ok) {
                    rejected.incrementAndGet();
                }
                byte[] body = (ok
                    ? "{\"lease_duration\":3600,\"data\":{\"username\":\"u\",\"password\":\"" + password + "\"}}"
                    : "{\"errors\":[\"permission denied\"]}").getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(ok ? 200 : 403, body.length);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(body);
                }
            });
            server.start();
            addr = "http://127.0.0.1:" + server.getAddress().getPort();
        }
    }
}
