package br.com.juantoledo.vaultjdbc;

import java.net.URI;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * Vault settings for one connection, resolved from {@code vault.*} options with the same
 * environment fallbacks the vault CLI uses (VAULT_ADDR, VAULT_NAMESPACE, VAULT_CACERT, VAULT_TOKEN).
 */
final class VaultConfig {
    static final String DEFAULT_MOUNT = "database";
    static final String DEFAULT_METHOD = "token";
    static final int DEFAULT_AUTH_RETRIES = 3;
    static final int DEFAULT_CACHE_SECONDS = 300;
    static final int DEFAULT_LOGIN_TIMEOUT_SECONDS = 120;

    private static final Pattern PATH_SEGMENTS = Pattern.compile("[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*");
    private static final Pattern LOGIN_ARG_KEY = Pattern.compile("[A-Za-z0-9_][A-Za-z0-9_.-]*");
    private static final Pattern SENSITIVE_KEY = Pattern.compile("(?i).*(pass|secret|token|key|otp|pin|cred).*");

    final URI addr;
    final String secretPath;
    final String namespace;
    final Path caCert;
    final Path tokenFile;
    final Path tokenDir;
    final String envToken;
    final String usernameKey;
    final String passwordKey;
    final int authRetries;
    final int cacheSeconds;
    final String method;
    final String authPath;
    final List<String> loginArgs;
    final boolean autoLogin;
    final String cli;
    final int loginTimeoutSeconds;

    private VaultConfig(Builder b) {
        this.addr = b.addr;
        this.secretPath = b.secretPath;
        this.namespace = b.namespace;
        this.caCert = b.caCert;
        this.tokenFile = b.tokenFile;
        this.tokenDir = b.tokenDir;
        this.envToken = b.envToken;
        this.usernameKey = b.usernameKey;
        this.passwordKey = b.passwordKey;
        this.authRetries = b.authRetries;
        this.cacheSeconds = b.cacheSeconds;
        this.method = b.method;
        this.authPath = b.authPath;
        this.loginArgs = b.loginArgs;
        this.autoLogin = b.autoLogin;
        this.cli = b.cli;
        this.loginTimeoutSeconds = b.loginTimeoutSeconds;
    }

    static VaultConfig from(VaultUrl url, Function<String, String> env) throws SQLException {
        Builder b = new Builder();

        String addr = firstNonBlank(url.option("addr"), env.apply("VAULT_ADDR"));
        if (addr == null) {
            throw new SQLException("Vault address not set: add vault.addr=https://... to the JDBC URL "
                + "(GUI apps usually do not inherit VAULT_ADDR from the shell)");
        }
        b.addr = URI.create(addr.replaceAll("/+$", ""));
        String scheme = b.addr.getScheme() == null ? "" : b.addr.getScheme().toLowerCase();
        if (!scheme.equals("https") && !(scheme.equals("http") && isLoopback(b.addr.getHost()))) {
            throw new SQLException("vault.addr must use https (plain http is only allowed for localhost)");
        }

        b.secretPath = secretPath(url);
        b.namespace = firstNonBlank(url.option("namespace"), env.apply("VAULT_NAMESPACE"));
        String caCert = firstNonBlank(url.option("cacert"), env.apply("VAULT_CACERT"));
        b.caCert = caCert == null ? null : expandHome(caCert, env);
        String tokenFile = url.option("tokenFile");
        b.tokenFile = expandHome(tokenFile == null ? "~/.vault-token" : tokenFile, env);
        b.tokenDir = expandHome(firstNonBlank(url.option("tokenDir"), firstNonBlank(env.apply("VAULT_JDBC_TOKEN_DIR"), "~/.vault-tokens")), env);
        // An explicit token file wins; otherwise behave like the vault CLI (VAULT_TOKEN over the file).
        b.envToken = tokenFile == null ? blankToNull(env.apply("VAULT_TOKEN")) : null;
        b.usernameKey = firstNonBlank(url.option("usernameKey"), "username");
        b.passwordKey = firstNonBlank(url.option("passwordKey"), "password");
        b.authRetries = parseInt(url.option("authRetries"), DEFAULT_AUTH_RETRIES, "vault.authRetries");
        b.cacheSeconds = parseInt(url.option("cacheSeconds"), DEFAULT_CACHE_SECONDS, "vault.cacheSeconds");

        // Same defaults as `vault login`: method "token", mounted at a path named after the method.
        String method = url.option("method");
        b.method = method == null ? DEFAULT_METHOD : validatePath(method, "vault.method");
        String authPath = url.option("authPath");
        b.authPath = authPath == null ? b.method : validatePath(authPath, "vault.authPath");
        b.loginArgs = loginArgs(url.option("loginArgs"));
        // The token method prompts on a terminal, so it cannot log in unattended.
        boolean canAutoLogin = !b.method.equals(DEFAULT_METHOD);
        b.autoLogin = parseBoolean(url.option("autoLogin"), canAutoLogin, "vault.autoLogin") && canAutoLogin;
        b.cli = url.option("cli");
        b.loginTimeoutSeconds = parseInt(url.option("loginTimeout"), DEFAULT_LOGIN_TIMEOUT_SECONDS, "vault.loginTimeout");
        return new VaultConfig(b);
    }

    /**
     * {@code vault.path} is a full secret path (KV or anything custom). Otherwise the database secrets
     * engine is assumed: {@code <vault.mount>/creds/<vault.role>}, or {@code static-creds} with vault.static=true.
     */
    private static String secretPath(VaultUrl url) throws SQLException {
        String path = url.option("path");
        String role = url.option("role");
        if (path != null && role != null) {
            throw new SQLException("Use either vault.role (database secrets engine) or vault.path (full secret path), not both");
        }
        if (path != null) {
            return validatePath(path.replaceAll("^/+", "").replaceAll("^v1/", ""), "vault.path");
        }
        if (role == null) {
            throw new SQLException("Missing vault.role (e.g. vault.role=my-role) or vault.path (e.g. vault.path=kv/data/app)");
        }
        String mount = validatePath(firstNonBlank(url.option("mount"), DEFAULT_MOUNT).replaceAll("^/+|/+$", ""), "vault.mount");
        boolean isStatic = parseBoolean(url.option("static"), false, "vault.static");
        return mount + (isStatic ? "/static-creds/" : "/creds/") + validatePath(role, "vault.role");
    }

    /** {@code vault.loginArgs=role=dba,scope=x} becomes {@code role=dba scope=x} on the vault login command line. */
    private static List<String> loginArgs(String value) throws SQLException {
        if (value == null) {
            return Collections.emptyList();
        }
        List<String> args = new ArrayList<>();
        for (String pair : value.split(",")) {
            String trimmed = pair.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            int eq = trimmed.indexOf('=');
            if (eq <= 0 || !LOGIN_ARG_KEY.matcher(trimmed.substring(0, eq)).matches()) {
                throw new SQLException("vault.loginArgs must be comma-separated key=value pairs");
            }
            args.add(trimmed);
        }
        return Collections.unmodifiableList(args);
    }

    /** Human-readable login command for logs and error messages; sensitive argument values are masked. */
    String loginCommand() {
        StringBuilder sb = new StringBuilder("vault login");
        if (!method.equals(DEFAULT_METHOD)) {
            sb.append(" -method=").append(method);
        }
        if (!authPath.equals(method)) {
            sb.append(" -path=").append(authPath);
        }
        for (String arg : loginArgs) {
            String key = arg.substring(0, arg.indexOf('='));
            sb.append(' ').append(SENSITIVE_KEY.matcher(key).matches() ? key + "=***" : arg);
        }
        return sb.toString();
    }

    /** Identifies credentials that can be shared between connections. */
    String cacheKey() {
        return String.join("|", serverKey(), secretPath);
    }

    /**
     * Per-server token file, so tokens for different Vault servers do not overwrite each other in ~/.vault-token.
     * The name must match contrib/vault-token-helper.sh: the address without trailing slashes, plus "|namespace"
     * when set, with every character outside [A-Za-z0-9._-] replaced by '_'.
     */
    Path serverTokenFile() {
        String key = addr.toString() + (namespace == null ? "" : "|" + namespace);
        return tokenDir.resolve(key.replaceAll("[^A-Za-z0-9._-]", "_"));
    }

    /** Identifies a Vault server (and namespace) for token reuse. */
    String serverKey() {
        return String.join("|", addr.toString(), Objects.toString(namespace, ""));
    }

    /** A single path segment such as a version number. */
    static String validateSegment(String value, String name) throws SQLException {
        if (!value.matches("[A-Za-z0-9._-]+") || value.contains("..")) {
            throw new SQLException(name + " may only contain letters, digits, '.', '_' and '-'");
        }
        return value;
    }

    private static String validatePath(String value, String name) throws SQLException {
        if (!PATH_SEGMENTS.matcher(value).matches() || value.contains("..")) {
            throw new SQLException(name + " may only contain letters, digits, '.', '_', '-' and '/'");
        }
        return value;
    }

    static boolean isLoopback(String host) {
        return host != null && (host.equals("localhost") || host.equals("127.0.0.1") || host.equals("[::1]") || host.equals("::1"));
    }

    private static Path expandHome(String value, Function<String, String> env) {
        if (value.equals("~") || value.startsWith("~/")) {
            String home = firstNonBlank(env.apply("HOME"), System.getProperty("user.home"));
            return Paths.get(home, value.substring(1));
        }
        return Paths.get(value);
    }

    private static int parseInt(String value, int fallback, String name) throws SQLException {
        if (value == null) {
            return fallback;
        }
        try {
            int parsed = Integer.parseInt(value);
            if (parsed < 0) {
                throw new NumberFormatException();
            }
            return parsed;
        } catch (NumberFormatException e) {
            throw new SQLException(name + " must be a non-negative integer");
        }
    }

    private static boolean parseBoolean(String value, boolean fallback, String name) throws SQLException {
        if (value == null) {
            return fallback;
        }
        if (value.equalsIgnoreCase("true")) {
            return true;
        }
        if (value.equalsIgnoreCase("false")) {
            return false;
        }
        throw new SQLException(name + " must be true or false");
    }

    private static String firstNonBlank(String a, String b) {
        String first = blankToNull(a);
        return first != null ? first : blankToNull(b);
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static final class Builder {
        URI addr;
        String secretPath;
        String namespace;
        Path caCert;
        Path tokenFile;
        Path tokenDir;
        String envToken;
        String usernameKey;
        String passwordKey;
        int authRetries;
        int cacheSeconds;
        String method;
        String authPath;
        List<String> loginArgs;
        boolean autoLogin;
        String cli;
        int loginTimeoutSeconds;
    }
}
