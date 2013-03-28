package org.bouncycastle.crypto.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.io.SignerInputStream;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * ECDHE key exchange (see RFC 4492)
 */
class TlsECDHEKeyExchange extends TlsECDHKeyExchange {

    protected TlsSignerCredentials serverCredentials = null;

    TlsECDHEKeyExchange(int keyExchange, int[] namedCurves, short[] clientECPointFormats,
        short[] serverECPointFormats) {
        super(keyExchange, namedCurves, clientECPointFormats, serverECPointFormats);
    }

    public void processServerCredentials(TlsCredentials serverCredentials) throws IOException {

        if (!(serverCredentials instanceof TlsSignerCredentials)) {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        processServerCertificate(serverCredentials.getCertificate());

        this.serverCredentials = (TlsSignerCredentials) serverCredentials;
    }

    public byte[] generateServerKeyExchange() throws IOException {

        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        // TODO Add support for arbitrary_explicit_*_curves

        short curveType = ECCurveType.named_curve;
        int namedCurve = chooseNamedCurve();
        ECDomainParameters curve_params = TlsECCUtils.getParametersForNamedCurve(namedCurve);
        ECCurve curve = curve_params.getCurve();

        ECKeyPairGenerator kpg = new ECKeyPairGenerator();
        kpg.init(new ECKeyGenerationParameters(curve_params, context.getSecureRandom()));
        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        this.ecAgreeServerPrivateKey = (ECPrivateKeyParameters) kp.getPrivate();

        byte[] publicBytes = serializeKey(clientECPointFormats,
            (ECPublicKeyParameters) kp.getPublic());

        TlsUtils.writeUint8(curveType, buf);
        TlsUtils.writeUint16(namedCurve, buf);
        TlsUtils.writeOpaque8(publicBytes, buf);

        byte[] digestInput = buf.toByteArray();

        Digest d = new CombinedHash();
        SecurityParameters securityParameters = context.getSecurityParameters();
        d.update(securityParameters.clientRandom, 0, securityParameters.clientRandom.length);
        d.update(securityParameters.serverRandom, 0, securityParameters.serverRandom.length);
        d.update(digestInput, 0, digestInput.length);

        byte[] hash = new byte[d.getDigestSize()];
        d.doFinal(hash, 0);

        byte[] sigBytes = serverCredentials.generateCertificateSignature(hash);
        TlsUtils.writeOpaque16(sigBytes, buf);

        return buf.toByteArray();
    }

    public void processServerKeyExchange(InputStream input) throws IOException {

        SecurityParameters securityParameters = context.getSecurityParameters();

        Signer signer = initSigner(tlsSigner, securityParameters);
        InputStream sigIn = new SignerInputStream(input, signer);

        short curveType = TlsUtils.readUint8(sigIn);

        // TODO Add support for explicit curve parameters (read from sigIn)
        if (curveType != ECCurveType.named_curve) {
            /*
             * NOTE: DefaultTlsClient by default doesn't offer support for
             * arbitrary_explicit_*_curves (see NamedCurve class), so the server can only validly
             * select ECCurveType.named_curve.
             */
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        int namedCurve = TlsUtils.readUint16(sigIn);
        if (!NamedCurve.refersToASpecificNamedCurve(namedCurve)) {
            /*
             * RFC 4492 5.4. All those values of NamedCurve are allowed that refer to a specific
             * curve. Values of NamedCurve that indicate support for a class of explicitly defined
             * curves are not allowed here [...].
             */
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        if (!TlsProtocol.arrayContains(namedCurves, namedCurve)) {
            /*
             * RFC 4492 4. [...] servers MUST NOT negotiate the use of an ECC cipher suite unless
             * they can complete the handshake while respecting the choice of curves and compression
             * techniques specified by the client.
             */
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        byte[] point = TlsUtils.readOpaque8(sigIn);

        byte[] sigByte = TlsUtils.readOpaque16(input);
        if (!signer.verifySignature(sigByte)) {
            throw new TlsFatalAlert(AlertDescription.bad_certificate);
        }

        ECDomainParameters curve_params = TlsECCUtils.getParametersForNamedCurve(namedCurve);

        /*
         * NOTE: Here we implicitly decode compressed or uncompressed encodings. DefaultTlsClient by
         * default is set up to advertise that we can parse any encoding so this works fine, but
         * extra checks might be needed here if that were changed.
         */
        ECPoint Ys = deserializeKey(curve_params, point);

        this.ecAgreeServerPublicKey = validateECPublicKey(new ECPublicKeyParameters(Ys,
            curve_params));
    }

    public void validateCertificateRequest(CertificateRequest certificateRequest)
        throws IOException {
        /*
         * RFC 4492 3. [...] The ECDSA_fixed_ECDH and RSA_fixed_ECDH mechanisms are usable with
         * ECDH_ECDSA and ECDH_RSA. Their use with ECDHE_ECDSA and ECDHE_RSA is prohibited because
         * the use of a long-term ECDH client key would jeopardize the forward secrecy property of
         * these algorithms.
         */
        short[] types = certificateRequest.getCertificateTypes();
        for (int i = 0; i < types.length; ++i) {
            switch (types[i]) {
            case ClientCertificateType.rsa_sign:
            case ClientCertificateType.dss_sign:
            case ClientCertificateType.ecdsa_sign:
                break;
            default:
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
        }
    }

    public void processClientCredentials(TlsCredentials clientCredentials) throws IOException {
        if (clientCredentials instanceof TlsSignerCredentials) {
            // OK
        } else {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    protected Signer initSigner(TlsSigner tlsSigner, SecurityParameters securityParameters) {
        Signer signer = tlsSigner.createVerifyer(this.serverPublicKey);
        signer.update(securityParameters.clientRandom, 0, securityParameters.clientRandom.length);
        signer.update(securityParameters.serverRandom, 0, securityParameters.serverRandom.length);
        return signer;
    }

    protected int chooseNamedCurve() throws IOException {
        if (namedCurves == null) {
            return NamedCurve.secp256r1;
        }
        for (int i = 0; i < namedCurves.length; ++i) {
            int namedCurve = namedCurves[i];
            if (TlsECCUtils.isSupportedNamedCurve(namedCurve)) {
                return namedCurve;
            }
        }
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }
}
