package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.tls.crypto.TlsSecret;

/**
 * A generic interface for key exchange implementations in (D)TLS.
 */
public interface TlsKeyExchange
{
    void init(TlsContext context);

    void skipServerCredentials()
        throws IOException;

    void processServerCredentials(TlsCredentials serverCredentials)
        throws IOException;

    void processServerCertificate(Certificate serverCertificate)
        throws IOException;

    boolean requiresServerKeyExchange();

    byte[] generateServerKeyExchange()
        throws IOException;

    void skipServerKeyExchange()
        throws IOException;

    void processServerKeyExchange(InputStream input)
        throws IOException;

    short[] getClientCertificateTypes();

    void skipClientCredentials()
        throws IOException;

    void processClientCredentials(TlsCredentials clientCredentials)
        throws IOException;

    void processClientCertificate(Certificate clientCertificate)
        throws IOException;

    void generateClientKeyExchange(OutputStream output)
        throws IOException;

    void processClientKeyExchange(InputStream input)
        throws IOException;

    boolean requiresCertificateVerify();

    TlsSecret generatePreMasterSecret()
        throws IOException;
}
