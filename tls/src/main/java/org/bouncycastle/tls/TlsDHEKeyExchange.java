package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.util.Vector;

import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.util.io.TeeInputStream;

public class TlsDHEKeyExchange
    extends TlsDHKeyExchange
{
    private static int checkKeyExchange(int keyExchange)
    {
        switch (keyExchange)
        {
        case KeyExchangeAlgorithm.DHE_DSS:
        case KeyExchangeAlgorithm.DHE_RSA:
            return keyExchange;
        default:
            throw new IllegalArgumentException("unsupported key exchange algorithm");
        }
    }

    protected TlsCredentialedSigner serverCredentials = null;
    protected TlsCertificate serverCertificate = null;

    public TlsDHEKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, TlsDHConfigVerifier dhConfigVerifier)
    {
        super(checkKeyExchange(keyExchange), supportedSignatureAlgorithms, dhConfigVerifier);
    }

    public TlsDHEKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, TlsDHConfig dhConfig)
    {
        super(checkKeyExchange(keyExchange), supportedSignatureAlgorithms, dhConfig);
    }

    public void processServerCredentials(TlsCredentials serverCredentials) throws IOException
    {
        if (!(serverCredentials instanceof TlsCredentialedSigner))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        this.serverCredentials = (TlsCredentialedSigner)serverCredentials;
    }

    public void processServerCertificate(Certificate serverCertificate) throws IOException
    {
        checkServerCertSigAlg(serverCertificate);

        this.serverCertificate = serverCertificate.getCertificateAt(0);
    }

    public byte[] generateServerKeyExchange() throws IOException
    {
        if (this.dhConfig == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        DigestInputBuffer digestBuffer = new DigestInputBuffer();

        TlsDHUtils.writeDHConfig(dhConfig, digestBuffer);

        this.agreement = context.getCrypto().createDHDomain(dhConfig).createDH();

        generateEphemeral(digestBuffer);

        TlsUtils.generateServerKeyExchangeSignature(context, serverCredentials, digestBuffer);

        return digestBuffer.toByteArray();
    }

    public void processServerKeyExchange(InputStream input) throws IOException
    {
        DigestInputBuffer digestBuffer = new DigestInputBuffer();
        InputStream teeIn = new TeeInputStream(input, digestBuffer);

        this.dhConfig = TlsDHUtils.receiveDHConfig(dhConfigVerifier, teeIn);

        byte[] y = TlsUtils.readOpaque16(teeIn);

        TlsUtils.verifyServerKeyExchangeSignature(context, input, keyExchange, supportedSignatureAlgorithms,
            serverCertificate, digestBuffer);

        this.agreement = context.getCrypto().createDHDomain(dhConfig).createDH();

        processEphemeral(y);
    }

    public short[] getClientCertificateTypes()
    {
        return new short[]{ ClientCertificateType.dss_sign, ClientCertificateType.ecdsa_sign,
            ClientCertificateType.rsa_sign };
    }

    public void processClientCredentials(TlsCredentials clientCredentials) throws IOException
    {
        if (clientCredentials instanceof TlsCredentialedSigner)
        {
            // OK
        }
        else
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }
}
