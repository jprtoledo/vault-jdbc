package br.com.juantoledo.vaultjdbc;

import br.com.juantoledo.vaultjdbc.VaultClient.Credential;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.DriverPropertyInfo;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.Properties;
import java.util.function.Function;
import java.util.logging.Logger;

/**
 * JDBC driver for URLs like {@code jdbc:vault:postgresql://host:5432/db?vault.addr=https://vault&vault.role=my-role}.
 * Every new physical connection gets a username/password from Vault and is handed to the real driver
 * with the {@code vault.*} parameters removed. If the database rejects a credential (expired or revoked
 * lease), a new one is fetched and the connection retried.
 */
public final class VaultDriver implements Driver {
    private static final Logger LOG = Logger.getLogger(VaultDriver.class.getName());
    private static final long FRESH_CREDENTIAL_MILLIS = 10_000;
    private static final long RETRY_BACKOFF_MILLIS = 1_000;

    private static final CredentialCache SHARED_CACHE = new CredentialCache(new VaultClient(new VaultLogin()), System::currentTimeMillis);
    private static final DriverResolver SHARED_RESOLVER = new DriverResolver(System::getenv);

    static {
        try {
            DriverManager.registerDriver(new VaultDriver());
        } catch (SQLException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private final CredentialCache cache;
    private final DriverResolver resolver;
    private final Function<String, String> env;
    private final Sleeper sleeper;

    public VaultDriver() {
        this(SHARED_CACHE, SHARED_RESOLVER, System::getenv, Thread::sleep);
    }

    VaultDriver(CredentialCache cache, DriverResolver resolver, Function<String, String> env, Sleeper sleeper) {
        this.cache = cache;
        this.resolver = resolver;
        this.env = env;
        this.sleeper = sleeper;
    }

    @Override
    public Connection connect(String url, Properties info) throws SQLException {
        if (!acceptsURL(url)) {
            return null;
        }
        VaultUrl parsed = VaultUrl.parse(url, info);
        VaultConfig config = VaultConfig.from(parsed, env);
        Driver delegate = resolver.resolve(parsed);

        Properties props = new Properties();
        if (info != null) {
            for (String name : info.stringPropertyNames()) {
                if (!name.startsWith(VaultUrl.OPTION_PREFIX) && !name.equals("user") && !name.equals("password")) {
                    props.setProperty(name, info.getProperty(name));
                }
            }
        }

        Credential credential = cache.get(config);
        boolean waited = false;
        for (int attempt = 0; ; attempt++) {
            props.setProperty("user", credential.username());
            props.setProperty("password", credential.password());
            try {
                Connection connection = delegate.connect(parsed.targetUrl, props);
                if (connection == null) {
                    throw new SQLException("Driver " + delegate.getClass().getName() + " does not accept " + parsed.targetUrl);
                }
                return connection;
            } catch (SQLException e) {
                if (!isAuthFailure(e) || attempt >= config.authRetries) {
                    throw e;
                }
                if (!waited && cache.ageMillis(credential) < FRESH_CREDENTIAL_MILLIS) {
                    // A just-issued user may not exist yet on the instance (e.g. Aurora reader lag): wait once, keep it.
                    LOG.fine(() -> "Fresh Vault credential rejected; retrying after backoff");
                    pause(RETRY_BACKOFF_MILLIS);
                    waited = true;
                } else {
                    LOG.fine(() -> "Vault credential rejected by the database; fetching a new one");
                    credential = cache.refresh(config, credential);
                    waited = false;
                }
            }
        }
    }

    static boolean isAuthFailure(SQLException error) {
        for (Throwable t = error; t != null; t = t.getCause()) {
            if (t instanceof SQLException sql) {
                String state = sql.getSQLState();
                // 28xxx = invalid authorization (PostgreSQL 28P01/28000, MySQL 28000); MySQL 1045 = access denied.
                if ((state != null && state.startsWith("28")) || sql.getErrorCode() == 1045) {
                    return true;
                }
            }
        }
        return false;
    }

    private void pause(long millis) throws SQLException {
        try {
            sleeper.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SQLException("Interrupted while retrying connection", e);
        }
    }

    @Override
    public boolean acceptsURL(String url) {
        return VaultUrl.accepts(url);
    }

    @Override
    public DriverPropertyInfo[] getPropertyInfo(String url, Properties info) {
        return new DriverPropertyInfo[0];
    }

    @Override
    public int getMajorVersion() {
        return 0;
    }

    @Override
    public int getMinorVersion() {
        return 1;
    }

    @Override
    public boolean jdbcCompliant() {
        return false;
    }

    @Override
    public Logger getParentLogger() throws SQLFeatureNotSupportedException {
        return Logger.getLogger("br.com.juantoledo.vaultjdbc");
    }

    @FunctionalInterface
    interface Sleeper {
        void sleep(long millis) throws InterruptedException;
    }
}
