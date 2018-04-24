package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Vector;

import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.io.Streams;

/**
 * (D)TLS RSA key exchange.
 */
public class TlsRSAKeyExchange
    extends AbstractTlsKeyExchange
{
    protected TlsCredentialedDecryptor serverCredentials = null;
    protected TlsCertificate serverCertificate;
    protected TlsSecret preMasterSecret;

    public TlsRSAKeyExchange(Vector supportedSignatureAlgorithms)
    {
        super(KeyExchangeAlgorithm.RSA, supportedSignatureAlgorithms);
    }

    public void skipServerCredentials()
        throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public void processServerCredentials(TlsCredentials serverCredentials)
        throws IOException
    {
        if (!(serverCredentials instanceof TlsCredentialedDecryptor))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        this.serverCredentials = (TlsCredentialedDecryptor)serverCredentials;
    }

    public void processServerCertificate(Certificate serverCertificate)
        throws IOException
    {
        if (serverCertificate.isEmpty())
        {
            throw new TlsFatalAlert(AlertDescription.bad_certificate);
        }

        checkServerCertSigAlg(serverCertificate);

        this.serverCertificate = serverCertificate.getCertificateAt(0).useInRole(ConnectionEnd.server, keyExchange);
    }

    public short[] getClientCertificateTypes()
    {
        return new short[]{ ClientCertificateType.rsa_sign, ClientCertificateType.dss_sign,
            ClientCertificateType.ecdsa_sign };
    }

    public void processClientCredentials(TlsCredentials clientCredentials)
        throws IOException
    {
        if (!(clientCredentials instanceof TlsCredentialedSigner))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public void generateClientKeyExchange(OutputStream output)
        throws IOException
    {
        this.preMasterSecret = TlsRSAUtils.generateEncryptedPreMasterSecret(context, serverCertificate, output);
    }

    public void processClientKeyExchange(InputStream input)
        throws IOException
    {
        byte[] encryptedPreMasterSecret = TlsUtils.readOpaque16(input);

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
