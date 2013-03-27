package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.io.Streams;

/**
 * TLS 1.0/1.1 and SSLv3 RSA key exchange.
 */
class TlsRSAKeyExchange extends AbstractTlsKeyExchange {
    protected AsymmetricKeyParameter serverPublicKey = null;

    protected RSAKeyParameters rsaServerPublicKey = null;

    protected TlsEncryptionCredentials serverCredentials = null;

    protected byte[] premasterSecret;

    TlsRSAKeyExchange() {
        super();
    }

    public void skipServerCredentials() throws IOException {
        throw new TlsFatalAlert(AlertDescription.unexpected_message);
    }

    public void processServerCredentials(TlsCredentials serverCredentials) throws IOException {

        if (!(serverCredentials instanceof TlsEncryptionCredentials)) {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        processServerCertificate(serverCredentials.getCertificate());

        this.serverCredentials = (TlsEncryptionCredentials) serverCredentials;
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

        // Sanity check the PublicKeyFactory
        if (this.serverPublicKey.isPrivate()) {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        this.rsaServerPublicKey = validateRSAPublicKey((RSAKeyParameters) this.serverPublicKey);

        TlsUtils.validateKeyUsage(x509Cert, KeyUsage.keyEncipherment);

        // TODO
        /*
         * Perform various checks per RFC2246 7.4.2: "Unless otherwise specified, the signing
         * algorithm for the certificate must be the same as the algorithm for the certificate key."
         */
    }

    public void validateCertificateRequest(CertificateRequest certificateRequest)
        throws IOException {
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
        if (!(clientCredentials instanceof TlsSignerCredentials)) {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public void generateClientKeyExchange(OutputStream os) throws IOException {
        this.premasterSecret = TlsRSAUtils.generateEncryptedPreMasterSecret(context,
            this.rsaServerPublicKey, os);
    }

    public void processClientKeyExchange(InputStream input) throws IOException {

        /*
         * NOTE: see RFC 4346 7.4.7.1 Implementation notes about SSLv3 and Bleichenbacher attacks
         */

        byte[] encryptedPreMasterSecret;
        if (context.getServerVersion().isSSL()) {
            // TODO Do any SSLv3 implementations actually include the length?
            encryptedPreMasterSecret = Streams.readAll(input);
        } else {
            encryptedPreMasterSecret = TlsUtils.readOpaque16(input);
        }

        try {
            this.premasterSecret = validatePremasterSecret(serverCredentials
                .decryptPreMasterSecret(encryptedPreMasterSecret));
        } catch (Exception e) {
            /*
             * "The best way to avoid vulnerability to this attack is to treat incorrectly formatted
             * messages in a manner indistinguishable from correctly formatted RSA blocks."
             */
            premasterSecret = new byte[48];
            context.getSecureRandom().nextBytes(premasterSecret);
        }
    }

    public byte[] generatePremasterSecret() throws IOException {
        if (this.premasterSecret == null) {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        byte[] tmp = this.premasterSecret;
        this.premasterSecret = null;
        return tmp;
    }

    // Would be needed to process RSA_EXPORT server key exchange
    // protected void processRSAServerKeyExchange(InputStream is, Signer signer) throws IOException
    // {
    // InputStream sigIn = is;
    // if (signer != null)
    // {
    // sigIn = new SignerInputStream(is, signer);
    // }
    //
    // byte[] modulusBytes = TlsUtils.readOpaque16(sigIn);
    // byte[] exponentBytes = TlsUtils.readOpaque16(sigIn);
    //
    // if (signer != null)
    // {
    // byte[] sigByte = TlsUtils.readOpaque16(is);
    //
    // if (!signer.verifySignature(sigByte))
    // {
    // handler.failWithError(AlertLevel.fatal, AlertDescription.bad_certificate);
    // }
    // }
    //
    // BigInteger modulus = new BigInteger(1, modulusBytes);
    // BigInteger exponent = new BigInteger(1, exponentBytes);
    //
    // this.rsaServerPublicKey = validateRSAPublicKey(new RSAKeyParameters(false, modulus,
    // exponent));
    // }

    protected byte[] validatePremasterSecret(byte[] premasterSecret) throws IOException {

        if (premasterSecret.length != 48) {
            throw new IllegalArgumentException("'premasterSecret' must be 48 bytes");
        }

        ProtocolVersion client_version = TlsUtils.readVersion(premasterSecret, 0);
        if (!client_version.equals(context.getClientVersion())) {
            throw new IllegalArgumentException(
                "'premasterSecret' version bytes must match ClientHello version");
        }

        return premasterSecret;
    }

    protected RSAKeyParameters validateRSAPublicKey(RSAKeyParameters key) throws IOException {
        // TODO What is the minimum bit length required?
        // key.getModulus().bitLength();

        if (!key.getExponent().isProbablePrime(2)) {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        return key;
    }
}
