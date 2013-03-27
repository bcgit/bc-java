package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;

import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

/**
 * ECDH key exchange (see RFC 4492)
 */
class TlsECDHKeyExchange extends AbstractTlsKeyExchange {

    protected TlsSigner tlsSigner;
    protected int keyExchange;
    protected int[] namedCurves;
    protected short[] ecPointFormats;

    protected AsymmetricKeyParameter serverPublicKey;
    protected ECPublicKeyParameters ecAgreeServerPublicKey;
    protected TlsAgreementCredentials agreementCredentials;
    protected ECPrivateKeyParameters ecAgreeClientPrivateKey;

    protected ECPrivateKeyParameters ecAgreeServerPrivateKey;
    protected ECPublicKeyParameters ecAgreeClientPublicKey;

    TlsECDHKeyExchange(int keyExchange, int[] namedCurves, short[] ecPointFormats) {
        super();

        switch (keyExchange) {
        case KeyExchangeAlgorithm.ECDHE_RSA:
            this.tlsSigner = new TlsRSASigner();
            break;
        case KeyExchangeAlgorithm.ECDHE_ECDSA:
            this.tlsSigner = new TlsECDSASigner();
            break;
        case KeyExchangeAlgorithm.ECDH_RSA:
        case KeyExchangeAlgorithm.ECDH_ECDSA:
            this.tlsSigner = null;
            break;
        default:
            throw new IllegalArgumentException("unsupported key exchange algorithm");
        }

        this.keyExchange = keyExchange;
        this.namedCurves = namedCurves;
        this.ecPointFormats = ecPointFormats;
    }

    public void skipServerCredentials() throws IOException {
        throw new TlsFatalAlert(AlertDescription.unexpected_message);
    }

    public void processServerCertificate(Certificate serverCertificate) throws IOException {

        if (serverCertificate.isEmpty()) {
            throw new TlsFatalAlert(AlertDescription.bad_certificate);
        }

        org.bouncycastle.asn1.x509.Certificate x509Cert = serverCertificate.getCertificateAt(0);

        SubjectPublicKeyInfo keyInfo = x509Cert.getSubjectPublicKeyInfo();
        try {
            this.serverPublicKey = PublicKeyFactory.createKey(keyInfo);
        } catch (RuntimeException e) {
            throw new TlsFatalAlert(AlertDescription.unsupported_certificate);
        }

        if (tlsSigner == null) {
            try {
                this.ecAgreeServerPublicKey = validateECPublicKey((ECPublicKeyParameters) this.serverPublicKey);
            } catch (ClassCastException e) {
                throw new TlsFatalAlert(AlertDescription.certificate_unknown);
            }

            TlsUtils.validateKeyUsage(x509Cert, KeyUsage.keyAgreement);
        } else {
            if (!tlsSigner.isValidPublicKey(this.serverPublicKey)) {
                throw new TlsFatalAlert(AlertDescription.certificate_unknown);
            }

            TlsUtils.validateKeyUsage(x509Cert, KeyUsage.digitalSignature);
        }

        // TODO
        /*
         * Perform various checks per RFC2246 7.4.2: "Unless otherwise specified, the signing
         * algorithm for the certificate must be the same as the algorithm for the certificate key."
         */
    }

    public boolean requiresServerKeyExchange() {
        switch (keyExchange) {
        case KeyExchangeAlgorithm.ECDHE_ECDSA:
        case KeyExchangeAlgorithm.ECDHE_RSA:
        case KeyExchangeAlgorithm.ECDH_anon:
            return true;
        default:
            return false;
        }
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
            case ClientCertificateType.rsa_fixed_ecdh:
            case ClientCertificateType.ecdsa_fixed_ecdh:
                break;
            default:
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
        }
    }

    public void processClientCredentials(TlsCredentials clientCredentials) throws IOException {
        if (clientCredentials instanceof TlsAgreementCredentials) {
            // TODO Validate client cert has matching parameters (see 'areOnSameCurve')?

            this.agreementCredentials = (TlsAgreementCredentials) clientCredentials;
        } else if (clientCredentials instanceof TlsSignerCredentials) {
            // OK
        } else {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public void generateClientKeyExchange(OutputStream os) throws IOException {
        if (agreementCredentials == null) {
            generateEphemeralClientKeyExchange(ecAgreeServerPublicKey.getParameters(), os);
        }
    }

    public void processClientCertificate(Certificate clientCertificate) throws IOException {
        // TODO Extract the public key
        // TODO If the certificate is 'fixed', take the public key as ecAgreeClientPublicKey
    }

    public void processClientKeyExchange(InputStream input) throws IOException {

        if (ecAgreeClientPublicKey != null) {
            // For ecdsa_fixed_ecdh and rsa_fixed_ecdh, the key arrived in the client certificate
            return;
        }

        byte[] keData = TlsUtils.readOpaque8(input);

        ECDomainParameters curve_params = this.ecAgreeServerPrivateKey.getParameters();
        ECPoint Yc = curve_params.getCurve().decodePoint(keData);
        this.ecAgreeClientPublicKey = validateECPublicKey(new ECPublicKeyParameters(Yc,
            curve_params));
    }

    public byte[] generatePremasterSecret() throws IOException {
        if (agreementCredentials != null) {
            return agreementCredentials.generateAgreement(ecAgreeServerPublicKey);
        }

        if (ecAgreeServerPrivateKey != null) {
            return calculateECDHBasicAgreement(ecAgreeClientPublicKey, ecAgreeServerPrivateKey);
        }

        if (ecAgreeClientPrivateKey != null) {
            return calculateECDHBasicAgreement(ecAgreeServerPublicKey, ecAgreeClientPrivateKey);
        }

        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    protected boolean areOnSameCurve(ECDomainParameters a, ECDomainParameters b) {
        // TODO Move to ECDomainParameters.equals() or other utility method?
        return a.getCurve().equals(b.getCurve()) && a.getG().equals(b.getG())
            && a.getN().equals(b.getN()) && a.getH().equals(b.getH());
    }

    protected byte[] serializeKey(ECPublicKeyParameters keyParameters) throws IOException {
        // TODO Add support for compressed encoding and SPF extension

        /*
         * RFC 4492 5.7. ...an elliptic curve point in uncompressed or compressed format. Here, the
         * format MUST conform to what the server has requested through a Supported Point Formats
         * Extension if this extension was used, and MUST be uncompressed if this extension was not
         * used.
         */
        return keyParameters.getQ().getEncoded();
    }

    protected AsymmetricCipherKeyPair generateECKeyPair(ECDomainParameters ecParams) {

        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
        ECKeyGenerationParameters keyGenerationParameters = new ECKeyGenerationParameters(ecParams,
            context.getSecureRandom());
        keyPairGenerator.init(keyGenerationParameters);
        return keyPairGenerator.generateKeyPair();
    }

    protected void generateEphemeralClientKeyExchange(ECDomainParameters ecParams, OutputStream os)
        throws IOException {

        AsymmetricCipherKeyPair ecAgreeClientKeyPair = generateECKeyPair(ecParams);
        this.ecAgreeClientPrivateKey = (ECPrivateKeyParameters) ecAgreeClientKeyPair.getPrivate();

        byte[] keData = serializeKey((ECPublicKeyParameters) ecAgreeClientKeyPair.getPublic());
        TlsUtils.writeOpaque8(keData, os);
    }

    protected byte[] calculateECDHBasicAgreement(ECPublicKeyParameters publicKey,
        ECPrivateKeyParameters privateKey) {

        ECDHBasicAgreement basicAgreement = new ECDHBasicAgreement();
        basicAgreement.init(privateKey);
        BigInteger agreement = basicAgreement.calculateAgreement(publicKey);
        return BigIntegers.asUnsignedByteArray(agreement);
    }

    protected ECPublicKeyParameters validateECPublicKey(ECPublicKeyParameters key)
        throws IOException {
        // TODO Check RFC 4492 for validation
        return key;
    }
}
