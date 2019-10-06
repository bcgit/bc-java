package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsSecret;

/**
 * (D)TLS RSA key exchange.
 */
public class TlsRSAKeyExchange
    extends AbstractTlsKeyExchange
{
    private static int checkKeyExchange(int keyExchange)
    {
        switch (keyExchange)
        {
        case KeyExchangeAlgorithm.RSA:
            return keyExchange;
        default:
            throw new IllegalArgumentException("unsupported key exchange algorithm");
        }
    }

    protected TlsCredentialedDecryptor serverCredentials = null;
    protected TlsCertificate serverCertificate;
    protected TlsSecret preMasterSecret;

    public TlsRSAKeyExchange(int keyExchange)
    {
        super(checkKeyExchange(keyExchange));
    }

    public void skipServerCredentials()
        throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public void processServerCredentials(TlsCredentials serverCredentials)
        throws IOException
    {
        this.serverCredentials = TlsUtils.requireDecryptorCredentials(serverCredentials);
    }

    public void processServerCertificate(Certificate serverCertificate)
        throws IOException
    {
        this.serverCertificate = serverCertificate.getCertificateAt(0).useInRole(ConnectionEnd.server,
            KeyExchangeAlgorithm.RSA);
    }

    public short[] getClientCertificateTypes()
    {
        return new short[]{ ClientCertificateType.rsa_sign, ClientCertificateType.dss_sign,
            ClientCertificateType.ecdsa_sign };
    }

    public void processClientCredentials(TlsCredentials clientCredentials)
        throws IOException
    {
        TlsUtils.requireSignerCredentials(clientCredentials);
    }

    public void generateClientKeyExchange(OutputStream output)
        throws IOException
    {
        this.preMasterSecret = TlsRSAUtils.generateEncryptedPreMasterSecret(context, serverCertificate, output);
    }

    public void processClientKeyExchange(InputStream input)
        throws IOException
    {
        byte[] encryptedPreMasterSecret = TlsUtils.readEncryptedPMS(context, input);

        this.preMasterSecret = serverCredentials.decrypt(new TlsCryptoParameters(context), encryptedPreMasterSecret);
    }

    public TlsSecret generatePreMasterSecret()
        throws IOException
    {
        TlsSecret tmp = this.preMasterSecret;
        this.preMasterSecret = null;
        return tmp;
    }
}
