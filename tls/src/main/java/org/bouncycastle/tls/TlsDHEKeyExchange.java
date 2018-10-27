package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Vector;

import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.io.TeeInputStream;

public class TlsDHEKeyExchange
    extends AbstractTlsKeyExchange
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

    protected TlsDHConfigVerifier dhConfigVerifier;
    protected TlsDHConfig dhConfig;

    protected TlsCredentialedSigner serverCredentials = null;
    protected TlsCertificate serverCertificate = null;
    protected TlsAgreement agreement;

    public TlsDHEKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, TlsDHConfigVerifier dhConfigVerifier)
    {
        this(keyExchange, supportedSignatureAlgorithms, dhConfigVerifier, null);
    }

    public TlsDHEKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, TlsDHConfig dhConfig)
    {
        this(keyExchange, supportedSignatureAlgorithms, null, dhConfig);
    }

    private TlsDHEKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, TlsDHConfigVerifier dhConfigVerifier,
        TlsDHConfig dhConfig)
    {
        super(checkKeyExchange(keyExchange), supportedSignatureAlgorithms);

        this.dhConfigVerifier = dhConfigVerifier;
        this.dhConfig = dhConfig;
    }

    public void skipServerCredentials() throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public void processServerCredentials(TlsCredentials serverCredentials) throws IOException
    {
        this.serverCredentials = TlsUtils.requireSignerCredentials(serverCredentials);
    }

    public void processServerCertificate(Certificate serverCertificate) throws IOException
    {
        this.serverCertificate = checkSigAlgOfServerCerts(serverCertificate);
    }

    public boolean requiresServerKeyExchange()
    {
        return true;
    }

    public byte[] generateServerKeyExchange() throws IOException
    {
        DigestInputBuffer digestBuffer = new DigestInputBuffer();

        TlsDHUtils.writeDHConfig(dhConfig, digestBuffer);

        this.agreement = context.getCrypto().createDHDomain(dhConfig).createDH();

        byte[] y = agreement.generateEphemeral();

        TlsUtils.writeOpaque16(y, digestBuffer);

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

        agreement.receivePeerValue(y);
    }

    public short[] getClientCertificateTypes()
    {
        return new short[]{ ClientCertificateType.dss_sign, ClientCertificateType.ecdsa_sign,
            ClientCertificateType.rsa_sign };
    }

    public void processClientCredentials(TlsCredentials clientCredentials) throws IOException
    {
        TlsUtils.requireSignerCredentials(clientCredentials);
    }

    public void generateClientKeyExchange(OutputStream output) throws IOException
    {
        byte[] y = agreement.generateEphemeral();

        TlsUtils.writeOpaque16(y, output);
    }

    public void processClientKeyExchange(InputStream input) throws IOException
    {
        agreement.receivePeerValue(TlsUtils.readOpaque16(input));
    }

    public TlsSecret generatePreMasterSecret() throws IOException
    {
        return agreement.calculateSecret();
    }
}
