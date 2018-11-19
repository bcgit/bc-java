package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsSecret;

/**
 * (D)TLS ECDH key exchange (see RFC 4492).
 */
public class TlsECDHKeyExchange
    extends AbstractTlsKeyExchange
{
    private static int checkKeyExchange(int keyExchange)
    {
        switch (keyExchange)
        {
        case KeyExchangeAlgorithm.ECDH_ECDSA:
        case KeyExchangeAlgorithm.ECDH_RSA:
            return keyExchange;
        default:
            throw new IllegalArgumentException("unsupported key exchange algorithm");
        }
    }

    protected TlsCredentialedAgreement agreementCredentials;
    protected TlsCertificate ecdhPeerCertificate;

    public TlsECDHKeyExchange(int keyExchange)
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
        this.ecdhPeerCertificate = serverCertificate.getCertificateAt(0).useInRole(ConnectionEnd.server, keyExchange);
    }

    public short[] getClientCertificateTypes()
    {
        /*
         * RFC 4492 3. [...] The ECDSA_fixed_ECDH and RSA_fixed_ECDH mechanisms are usable with
         * ECDH_ECDSA and ECDH_RSA. Their use with ECDHE_ECDSA and ECDHE_RSA is prohibited because
         * the use of a long-term ECDH client key would jeopardize the forward secrecy property of
         * these algorithms.
         */
        return new short[]{ ClientCertificateType.ecdsa_fixed_ecdh, ClientCertificateType.rsa_fixed_ecdh };
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
        // In this case, the Client Key Exchange message will be sent, but will be empty.
    }

    public void processClientCertificate(Certificate clientCertificate) throws IOException
    {
        this.ecdhPeerCertificate = clientCertificate.getCertificateAt(0)
            .useInRole(ConnectionEnd.client, keyExchange);
    }

    public void processClientKeyExchange(InputStream input) throws IOException
    {
        // For ecdsa_fixed_ecdh and rsa_fixed_ecdh, the key arrived in the client certificate
    }

    public boolean requiresCertificateVerify()
    {
        return false;
    }

    public TlsSecret generatePreMasterSecret() throws IOException
    {
        return agreementCredentials.generateAgreement(ecdhPeerCertificate);
    }
}
