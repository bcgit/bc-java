package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.util.Vector;

import org.bouncycastle.util.io.TeeInputStream;

/**
 * (D)TLS ECDHE key exchange (see RFC 4492).
 */
public class TlsECDHEKeyExchange
    extends TlsECDHKeyExchange
{
    protected TlsSignerCredentials serverCredentials = null;

    public TlsECDHEKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, int[] namedCurves,
        short[] clientECPointFormats, short[] serverECPointFormats)
    {
        super(keyExchange, supportedSignatureAlgorithms, namedCurves, clientECPointFormats, serverECPointFormats);
    }

    public void processServerCredentials(TlsCredentials serverCredentials)
        throws IOException
    {
        if (!(serverCredentials instanceof TlsSignerCredentials))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        processServerCertificate(serverCredentials.getCertificate());

        this.serverCredentials = (TlsSignerCredentials)serverCredentials;
    }

    public byte[] generateServerKeyExchange() throws IOException
    {
        DigestInputBuffer buf = new DigestInputBuffer();

        this.ecConfig = TlsECCUtils.selectECConfig(namedCurves, clientECPointFormats, buf);

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

        this.ecConfig = TlsECCUtils.receiveECConfig(namedCurves, serverECPointFormats, teeIn);

        byte[] point = TlsUtils.readOpaque8(teeIn);

        DigitallySigned signedParams = parseSignature(input);

        TlsUtils.verifyServerKeyExchangeSignature(context, tlsSigner, serverPublicKey, buf, signedParams);

        this.agreement = context.getCrypto().createECDomain(ecConfig).createECDH();

        processEphemeral(clientECPointFormats, point);
    }

    public void validateCertificateRequest(CertificateRequest certificateRequest)
        throws IOException
    {
        /*
         * RFC 4492 3. [...] The ECDSA_fixed_ECDH and RSA_fixed_ECDH mechanisms are usable with
         * ECDH_ECDSA and ECDH_RSA. Their use with ECDHE_ECDSA and ECDHE_RSA is prohibited because
         * the use of a long-term ECDH client key would jeopardize the forward secrecy property of
         * these algorithms.
         */
        short[] types = certificateRequest.getCertificateTypes();
        for (int i = 0; i < types.length; ++i)
        {
            switch (types[i])
            {
            case ClientCertificateType.rsa_sign:
            case ClientCertificateType.dss_sign:
            case ClientCertificateType.ecdsa_sign:
                break;
            default:
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
        }
    }

    public void processClientCredentials(TlsCredentials clientCredentials)
        throws IOException
    {
        if (clientCredentials instanceof TlsSignerCredentials)
        {
            // OK
        }
        else
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }
}
