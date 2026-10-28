package br.com.juantoledo.vaultjdbc;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

/**
 * Splits {@code jdbc:vault:<subprotocol>://...?vault.path=...&other=...} into the target JDBC URL
 * (with every {@code vault.*} parameter removed) and the Vault options.
 * Options may also come from connection properties; URL parameters win.
 */
final class VaultUrl {
    static final String PREFIX = "jdbc:vault:";
    static final String OPTION_PREFIX = "vault.";

    final String targetUrl;
    final String subprotocol;
    final Map<String, String> options;

    private VaultUrl(String targetUrl, String subprotocol, Map<String, String> options) {
        this.targetUrl = targetUrl;
        this.subprotocol = subprotocol;
        this.options = options;
    }

    static boolean accepts(String url) {
        return url != null && url.regionMatches(true, 0, PREFIX, 0, PREFIX.length());
    }

    static VaultUrl parse(String url, Properties info) throws SQLException {
        if (!accepts(url)) {
            throw new SQLException("Not a vault-jdbc URL; expected prefix " + PREFIX);
        }
        String rest = url.substring(PREFIX.length());
        int colon = rest.indexOf(':');
        if (colon <= 0) {
            throw new SQLException("Missing target subprotocol, e.g. jdbc:vault:postgresql://host/db");
        }
        String subprotocol = rest.substring(0, colon).toLowerCase();

        Map<String, String> options = new LinkedHashMap<>();
        if (info != null) {
            for (String name : info.stringPropertyNames()) {
                if (name.startsWith(OPTION_PREFIX)) {
                    options.put(name.substring(OPTION_PREFIX.length()), info.getProperty(name));
                }
            }
        }

        String base = rest;
        StringBuilder keptQuery = new StringBuilder();
        int question = rest.indexOf('?');
        if (question >= 0) {
            base = rest.substring(0, question);
            for (String pair : rest.substring(question + 1).split("&")) {
                if (pair.isEmpty()) {
                    continue;
                }
                int eq = pair.indexOf('=');
                String key = decode(eq >= 0 ? pair.substring(0, eq) : pair);
                if (key.startsWith(OPTION_PREFIX)) {
                    options.put(key.substring(OPTION_PREFIX.length()), eq >= 0 ? decode(pair.substring(eq + 1)) : "");
                } else {
                    keptQuery.append(keptQuery.length() == 0 ? "" : "&").append(pair);
                }
            }
        }
        String target = "jdbc:" + base + (keptQuery.length() > 0 ? "?" + keptQuery : "");
        return new VaultUrl(target, subprotocol, options);
    }

    String option(String name) {
        String value = options.get(name);
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static String decode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }
}
