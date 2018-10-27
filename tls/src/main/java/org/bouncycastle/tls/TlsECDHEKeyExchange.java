package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Vector;

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

    protected TlsECConfigVerifier ecConfigVerifier;
    protected TlsECConfig ecConfig;
    protected short[] clientECPointFormats, serverECPointFormats;

    protected TlsCredentialedSigner serverCredentials = null;
    protected TlsCertificate serverCertificate = null;
    protected TlsAgreement agreement;

    public TlsECDHEKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsECConfigVerifier ecConfigVerifier, short[] clientECPointFormats, short[] serverECPointFormats)
    {
        this(keyExchange, supportedSignatureAlgorithms, ecConfigVerifier, null, clientECPointFormats,
            serverECPointFormats);
    }

    public TlsECDHEKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, TlsECConfig ecConfig,
        short[] serverECPointFormats)
    {
        this(keyExchange, supportedSignatureAlgorithms, null, ecConfig, null, serverECPointFormats);
    }

    private TlsECDHEKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsECConfigVerifier ecConfigVerifier, TlsECConfig ecConfig, short[] clientECPointFormats,
        short[] serverECPointFormats)
    {
        super(checkKeyExchange(keyExchange), supportedSignatureAlgorithms);

        this.ecConfigVerifier = ecConfigVerifier;
        this.ecConfig = ecConfig;
        this.clientECPointFormats = clientECPointFormats;
        this.serverECPointFormats = serverECPointFormats;
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

        this.ecConfig = TlsECCUtils.receiveECConfig(ecConfigVerifier, serverECPointFormats, teeIn);

        byte[] point = TlsUtils.readOpaque8(teeIn);

        TlsUtils.verifyServerKeyExchangeSignature(context, input, keyExchange, supportedSignatureAlgorithms,
            serverCertificate, digestBuffer);

        this.agreement = context.getCrypto().createECDomain(ecConfig).createECDH();

        processEphemeral(clientECPointFormats, point);
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
        byte[] point = TlsUtils.readOpaque8(input);

        processEphemeral(serverECPointFormats, point);
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

    protected void processEphemeral(short[] localECPointFormats, byte[] point) throws IOException
    {
        TlsECCUtils.checkPointEncoding(localECPointFormats, ecConfig.getNamedGroup(), point);

        this.agreement.receivePeerValue(point);
    }
}
