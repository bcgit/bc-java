package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.util.Vector;

import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.tls.crypto.TlsVerifier;
import org.bouncycastle.util.io.TeeInputStream;

/**
 * (D)TLS ECDHE key exchange (see RFC 4492).
 */
public class TlsECDHEKeyExchange
    extends TlsECDHKeyExchange
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

    protected TlsCredentialedSigner serverCredentials = null;
    protected TlsVerifier verifier = null;

    public TlsECDHEKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsECConfigVerifier ecConfigVerifier, short[] clientECPointFormats, short[] serverECPointFormats)
    {
        super(checkKeyExchange(keyExchange), supportedSignatureAlgorithms, ecConfigVerifier, clientECPointFormats,
            serverECPointFormats);
    }

    public TlsECDHEKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, TlsECConfig ecConfig,
        short[] serverECPointFormats)
    {
        super(checkKeyExchange(keyExchange), supportedSignatureAlgorithms, ecConfig, serverECPointFormats);
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
        if (serverCertificate.isEmpty())
        {
            throw new TlsFatalAlert(AlertDescription.bad_certificate);
        }

        checkServerCertSigAlg(serverCertificate);

        this.verifier = serverCertificate.getCertificateAt(0)
            .createVerifier(TlsUtils.getSignatureAlgorithm(keyExchange));
    }

    public byte[] generateServerKeyExchange() throws IOException
    {
        DigestInputBuffer buf = new DigestInputBuffer();

        TlsECCUtils.writeECConfig(ecConfig, buf);

        this.agreement = context.getCrypto().createECDomain(ecConfig).createECDH();

        generateEphemeral(buf);

        DigitallySigned signedParams = TlsUtils.generateServerKeyExchangeSignature(context, serverCredentials, buf);

        signedParams.encode(buf);

        return buf.toByteArray();
    }

    public void processServerKeyExchange(InputStream input) throws IOException
    {
        DigestInputBuffer buf = new DigestInputBuffer();
        InputStream teeIn = new TeeInputStream(input, buf);

        this.ecConfig = TlsECCUtils.receiveECConfig(ecConfigVerifier, serverECPointFormats, teeIn);

        byte[] point = TlsUtils.readOpaque8(teeIn);

        DigitallySigned signedParams = parseSignature(input);

        TlsUtils.verifyServerKeyExchangeSignature(context, verifier, buf, signedParams);

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
