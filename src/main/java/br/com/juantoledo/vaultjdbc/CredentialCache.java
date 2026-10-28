package br.com.juantoledo.vaultjdbc;

import br.com.juantoledo.vaultjdbc.VaultClient.Credential;
import java.sql.SQLException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;
import java.util.logging.Logger;

/**
 * Shares one Vault credential between all connections of the same Vault path, so a connection pool
 * opening several connections at once does not create one database user per connection.
 * A credential is replaced once most of its lease has elapsed, or on demand after an auth failure.
 */
final class CredentialCache {
    private static final Logger LOG = Logger.getLogger(CredentialCache.class.getName());
    private static final long MIN_REMAINING_MILLIS = 30_000;

    private final VaultClient client;
    private final LongSupplier clock;
    private final Map<String, Entry> entries = new ConcurrentHashMap<>();

    CredentialCache(VaultClient client, LongSupplier clock) {
        this.client = client;
        this.clock = clock;
    }

    Credential get(VaultConfig config) throws SQLException {
        return entries.computeIfAbsent(config.cacheKey(), key -> new Entry()).get(config, null);
    }

    long ageMillis(Credential credential) {
        return clock.getAsLong() - credential.fetchedAtMillis();
    }

    /** Fetches a new credential unless another thread already replaced {@code rejected}. */
    Credential refresh(VaultConfig config, Credential rejected) throws SQLException {
        return entries.computeIfAbsent(config.cacheKey(), key -> new Entry()).get(config, rejected);
    }

    private final class Entry {
        private Credential current;

        synchronized Credential get(VaultConfig config, Credential rejected) throws SQLException {
            boolean replace = current == null || current == rejected || expiresSoon(current, config);
            if (replace) {
                current = client.read(config).fetchedAt(clock.getAsLong());
                LOG.fine(() -> "Fetched credential from Vault path " + config.secretPath + " (" + current + ")");
            }
            return current;
        }

        private boolean expiresSoon(Credential credential, VaultConfig config) {
            long lifetime = (credential.leaseSeconds() > 0 ? credential.leaseSeconds() : config.cacheSeconds) * 1000L;
            long expiresAt = credential.fetchedAtMillis() + lifetime;
            // Refresh with 20% of the lease (at least 30s) left, so new connections never get a dying user.
            long margin = Math.max(MIN_REMAINING_MILLIS, lifetime / 5);
            return clock.getAsLong() >= expiresAt - margin;
        }
    }
}
