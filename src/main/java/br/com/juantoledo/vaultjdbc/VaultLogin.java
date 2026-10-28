package br.com.juantoledo.vaultjdbc;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * Runs {@code vault login -method=<m> -path=<p> [k=v...]} the way a user would, so browser-based methods
 * such as OIDC pop up the identity provider. The CLI still stores the token through its token helper
 * (normally ~/.vault-token), and the token is also read from its JSON output so this process can use it
 * even with a custom vault.tokenFile or a stale VAULT_TOKEN.
 */
class VaultLogin {
    private static final Logger LOG = Logger.getLogger(VaultLogin.class.getName());
    private static final int MAX_OUTPUT_BYTES = 256 * 1024;
    private static final String[] EXTRA_CLI_DIRS = {"/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/snap/bin"};

    /** Logs in and returns the new client token. */
    String login(VaultConfig config) throws SQLException {
        List<String> command = new ArrayList<>();
        command.add(resolveCli(config));
        command.add("login");
        command.add("-format=json");
        command.add("-method=" + config.method);
        command.add("-path=" + config.authPath);
        command.addAll(config.loginArgs);

        ProcessBuilder builder = new ProcessBuilder(command);
        Map<String, String> env = builder.environment();
        env.remove("VAULT_TOKEN");
        env.put("VAULT_ADDR", config.addr.toString());
        if (config.namespace != null) {
            env.put("VAULT_NAMESPACE", config.namespace);
        }
        if (config.caCert != null) {
            env.put("VAULT_CACERT", config.caCert.toString());
        }

        LOG.info(() -> "Vault token missing or expired; running: " + config.loginCommand());
        Process process;
        try {
            process = builder.start();
        } catch (IOException e) {
            throw new SQLException("Could not start the vault CLI (" + command.get(0) + "): " + e.getMessage()
                + ". Set vault.cli=/path/to/vault or run: " + config.loginCommand(), "28000", e);
        }
        try {
            // No terminal: methods that would prompt for a password fail fast instead of hanging.
            process.getOutputStream().close();
            CompletableFuture<byte[]> stdout = CompletableFuture.supplyAsync(() -> readBounded(process.getInputStream()));
            CompletableFuture<byte[]> stderr = CompletableFuture.supplyAsync(() -> readBounded(process.getErrorStream()));
            if (!process.waitFor(config.loginTimeoutSeconds, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                throw new SQLException("vault login did not finish within " + config.loginTimeoutSeconds
                    + "s (vault.loginTimeout). Run it manually: " + config.loginCommand(), "28000");
            }
            String out = new String(stdout.join(), StandardCharsets.UTF_8);
            String err = new String(stderr.join(), StandardCharsets.UTF_8);
            if (process.exitValue() != 0) {
                throw new SQLException("vault login failed (exit " + process.exitValue() + "): " + lastLine(err)
                    + ". Run it manually: " + config.loginCommand(), "28000");
            }
            return clientToken(out, config);
        } catch (InterruptedException e) {
            process.destroyForcibly();
            Thread.currentThread().interrupt();
            throw new SQLException("Interrupted while waiting for vault login", "28000", e);
        } catch (IOException e) {
            process.destroyForcibly();
            throw new SQLException("Could not talk to the vault CLI: " + e.getMessage(), "28000", e);
        }
    }

    private static String clientToken(String stdout, VaultConfig config) throws SQLException {
        try {
            Object root = Json.parse(stdout.trim());
            Object auth = root instanceof Map<?, ?> map ? map.get("auth") : null;
            Object token = auth instanceof Map<?, ?> map ? map.get("client_token") : null;
            if (token instanceof String value && !value.isBlank()) {
                return value;
            }
        } catch (IllegalArgumentException ignored) {
            // fall through; never echo stdout, it holds the token
        }
        throw new SQLException("vault login succeeded but printed no token; run it manually: " + config.loginCommand(), "28000");
    }

    /** vault.cli, else the first "vault" on PATH or in common install dirs (GUI apps often get a minimal PATH). */
    static String resolveCli(VaultConfig config) throws SQLException {
        if (config.cli != null) {
            return config.cli;
        }
        boolean windows = System.getProperty("os.name", "").toLowerCase().startsWith("windows");
        String binary = windows ? "vault.exe" : "vault";
        List<String> dirs = new ArrayList<>();
        String path = System.getenv("PATH");
        if (path != null) {
            for (String dir : path.split(java.io.File.pathSeparator)) {
                dirs.add(dir);
            }
        }
        if (!windows) {
            dirs.addAll(List.of(EXTRA_CLI_DIRS));
        }
        for (String dir : dirs) {
            if (dir.isEmpty()) {
                continue;
            }
            Path candidate = Paths.get(dir, binary);
            if (Files.isRegularFile(candidate) && Files.isExecutable(candidate)) {
                return candidate.toString();
            }
        }
        throw new SQLException("vault CLI not found on PATH; set vault.cli=/path/to/vault or run: " + config.loginCommand(), "28000");
    }

    private static byte[] readBounded(InputStream in) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        try (in) {
            int n;
            while ((n = in.read(buffer)) != -1) {
                if (out.size() < MAX_OUTPUT_BYTES) {
                    out.write(buffer, 0, Math.min(n, MAX_OUTPUT_BYTES - out.size()));
                }
            }
        } catch (IOException ignored) {
            // process went away; return what we have
        }
        return out.toByteArray();
    }

    private static String lastLine(String text) {
        String[] lines = text.strip().split("\\R");
        return lines.length == 0 || lines[lines.length - 1].isBlank() ? "no output" : lines[lines.length - 1].strip();
    }
}
