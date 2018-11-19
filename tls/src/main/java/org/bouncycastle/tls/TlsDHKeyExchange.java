package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsSecret;

/**
 * (D)TLS DH key exchange.
 */
public class TlsDHKeyExchange
    extends AbstractTlsKeyExchange
{
    private static int checkKeyExchange(int keyExchange)
    {
        switch (keyExchange)
        {
        case KeyExchangeAlgorithm.DH_DSS:
        case KeyExchangeAlgorithm.DH_RSA:
            return keyExchange;
        default:
            throw new IllegalArgumentException("unsupported key exchange algorithm");
        }
    }

    protected TlsCredentialedAgreement agreementCredentials;
    protected TlsCertificate dhPeerCertificate;

    public TlsDHKeyExchange(int keyExchange)
    {
        super(checkKeyExchange(keyExchange));
    }

    public void skipServerCredentials() throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public void processServerCredentials(TlsCredentials serverCredentials) throws IOException
    {
        this.agreementCredentials = TlsUtils.requireAgreementCredentials(serverCredentials);
    }

    public void processServerCertificate(Certificate serverCertificate) throws IOException
    {
        this.dhPeerCertificate = serverCertificate.getCertificateAt(0).useInRole(ConnectionEnd.server, keyExchange);
    }

    public short[] getClientCertificateTypes()
    {
        return new short[]{ ClientCertificateType.dss_fixed_dh, ClientCertificateType.rsa_fixed_dh };
    }

    public void skipClientCredentials() throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.unexpected_message);
    }

    public void processClientCredentials(TlsCredentials clientCredentials) throws IOException
    {
        this.agreementCredentials = TlsUtils.requireAgreementCredentials(clientCredentials);
    }

    public void generateClientKeyExchange(OutputStream output) throws IOException
    {
        /*
         * RFC 2246 7.4.7.2 If the client certificate already contains a suitable Diffie-Hellman
         * key, then Yc is implicit and does not need to be sent again. In this case, the Client Key
         * Exchange message will be sent, but will be empty.
         */
    }

    public void processClientCertificate(Certificate clientCertificate) throws IOException
    {
        this.dhPeerCertificate = clientCertificate.getCertificateAt(0)
            .useInRole(ConnectionEnd.client, keyExchange);
    }

    public void processClientKeyExchange(InputStream input) throws IOException
    {
        // For dss_fixed_dh and rsa_fixed_dh, the key arrived in the client certificate
    }

    public boolean requiresCertificateVerify()
    {
        return false;
    }

    public TlsSecret generatePreMasterSecret() throws IOException
    {
        return agreementCredentials.generateAgreement(dhPeerCertificate);
    }
}
