package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.io.TeeInputStream;

/**
 * (D)TLS ECDHE key exchange (see RFC 4492).
 */
public class TlsECDHEKeyExchange
    extends AbstractTlsKeyExchange
{
    private static int checkKeyExchange(int keyExchange)
    {
        switch (keyExchange)
        {
        case KeyExchangeAlgorithm.ECDHE_ECDSA:
        case KeyExchangeAlgorithm.ECDHE_RSA:
            return keyExchange;
        default:
            throw new IllegalArgumentException("unsupported key exchange algorithm");
        }
    }

    protected TlsECConfig ecConfig;

    protected TlsCredentialedSigner serverCredentials = null;
    protected TlsCertificate serverCertificate = null;
    protected TlsAgreement agreement;

    public TlsECDHEKeyExchange(int keyExchange)
    {
        this(keyExchange, null);
    }

    public TlsECDHEKeyExchange(int keyExchange, TlsECConfig ecConfig)
    {
        super(checkKeyExchange(keyExchange));

        this.ecConfig = ecConfig;
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
        this.serverCertificate = serverCertificate.getCertificateAt(0);
    }

    public boolean requiresServerKeyExchange()
    {
        return true;
    }

    public byte[] generateServerKeyExchange() throws IOException
    {
        DigestInputBuffer digestBuffer = new DigestInputBuffer();

        TlsECCUtils.writeECConfig(ecConfig, digestBuffer);

        this.agreement = context.getCrypto().createECDomain(ecConfig).createECDH();

        generateEphemeral(digestBuffer);

        TlsUtils.generateServerKeyExchangeSignature(context, serverCredentials, digestBuffer);

        return digestBuffer.toByteArray();
    }

    public void processServerKeyExchange(InputStream input) throws IOException
    {
        DigestInputBuffer digestBuffer = new DigestInputBuffer();
        InputStream teeIn = new TeeInputStream(input, digestBuffer);

        this.ecConfig = TlsECCUtils.receiveECDHConfig(context, teeIn);

        byte[] point = TlsUtils.readOpaque8(teeIn, 1);

        TlsUtils.verifyServerKeyExchangeSignature(context, input, serverCertificate, digestBuffer);

        this.agreement = context.getCrypto().createECDomain(ecConfig).createECDH();

        processEphemeral(point);
    }

    public short[] getClientCertificateTypes()
    {
        /*
         * RFC 4492 3. [...] The ECDSA_fixed_ECDH and RSA_fixed_ECDH mechanisms are usable with
         * ECDH_ECDSA and ECDH_RSA. Their use with ECDHE_ECDSA and ECDHE_RSA is prohibited because
         * the use of a long-term ECDH client key would jeopardize the forward secrecy property of
         * these algorithms.
         */
        return new short[]{ ClientCertificateType.dss_sign, ClientCertificateType.ecdsa_sign,
            ClientCertificateType.rsa_sign };
    }

    public void processClientCredentials(TlsCredentials clientCredentials) throws IOException
    {
        TlsUtils.requireSignerCredentials(clientCredentials);
    }

    public void generateClientKeyExchange(OutputStream output) throws IOException
    {
        generateEphemeral(output);
    }

    public void processClientKeyExchange(InputStream input) throws IOException
    {
        byte[] point = TlsUtils.readOpaque8(input, 1);

        processEphemeral(point);
    }

    public TlsSecret generatePreMasterSecret() throws IOException
    {
        return agreement.calculateSecret();
    }

    protected void generateEphemeral(OutputStream output) throws IOException
    {
        byte[] point = agreement.generateEphemeral();

        TlsUtils.writeOpaque8(point, output);
    }

    protected void processEphemeral(byte[] point) throws IOException
    {
        TlsECCUtils.checkPointEncoding(ecConfig.getNamedGroup(), point);

        this.agreement.receivePeerValue(point);
    }
}
