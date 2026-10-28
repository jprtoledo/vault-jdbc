package br.com.juantoledo.vaultjdbc;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * Builds an SSLContext that trusts the JDK's default CAs plus the certificates in a PEM or DER file,
 * e.g. a company CA or a TLS-inspecting proxy such as Zscaler. Certificate and hostname checks stay on.
 */
final class TlsTrust {
    private TlsTrust() {
    }

    static SSLContext withExtraCertificates(Path file) throws SQLException {
        try {
            KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
            store.load(null, null);
            int index = 0;
            for (X509Certificate cert : defaultTrustManager().getAcceptedIssuers()) {
                store.setCertificateEntry("default-" + index++, cert);
            }
            int added = 0;
            try (InputStream in = Files.newInputStream(file)) {
                for (Certificate cert : CertificateFactory.getInstance("X.509").generateCertificates(in)) {
                    store.setCertificateEntry("extra-" + added++, cert);
                }
            }
            if (added == 0) {
                throw new SQLException("No certificates found in " + file);
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(store);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, tmf.getTrustManagers(), null);
            return context;
        } catch (IOException | GeneralSecurityException e) {
            throw new SQLException("Could not load CA certificate " + file + ": " + e.getMessage(), e);
        }
    }

    private static X509TrustManager defaultTrustManager() throws GeneralSecurityException {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((KeyStore) null);
        for (TrustManager manager : tmf.getTrustManagers()) {
            if (manager instanceof X509TrustManager x509) {
                return x509;
            }
        }
        throw new GeneralSecurityException("No default X509TrustManager");
    }
}
