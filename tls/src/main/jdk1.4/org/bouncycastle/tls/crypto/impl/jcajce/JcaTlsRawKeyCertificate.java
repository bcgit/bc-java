package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.interfaces.DHPublicKey;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.Tls13Verifier;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCertificateRole;
import org.bouncycastle.tls.crypto.TlsEncryptor;
import org.bouncycastle.tls.crypto.TlsVerifier;
import org.bouncycastle.tls.crypto.impl.LegacyTls13Verifier;
import org.bouncycastle.tls.crypto.impl.PQCUtil;
import org.bouncycastle.tls.crypto.impl.RSAUtil;

/**
 * Implementation class for a raw public key (RFC 7250) based on the JCA. The certificate is just a
 * DER-encoded SubjectPublicKeyInfo, with no X.509 metadata: it has no serial number, signature
 * algorithm, extensions or KeyUsage, so all signature/encryption uses are permitted by the key
 * itself.
 * <p>
 * This is the base class for {@link JcaTlsCertificate} (an X.509 certificate is a SubjectPublicKeyInfo
 * plus X.509 metadata); subclasses override {@link #getPublicKey()},
 * {@link #getSubjectPublicKeyInfo()}, {@link #supportsKeyUsageBit(int)} and the X.509 accessors
 * ({@link #getEncoded()}, {@link #getExtension(ASN1ObjectIdentifier)}, {@link #getSerialNumber()},
 * {@link #getSigAlgOID()}, {@link #getSigAlgParams()}) to source them from the certificate. This
 * mirrors the lightweight {@code BcTlsCertificate extends BcTlsRawKeyCertificate} structure.
 */
public class JcaTlsRawKeyCertificate
    implements TlsCertificate
{
    protected static final int KU_DIGITAL_SIGNATURE = 0;
    protected static final int KU_NON_REPUDIATION = 1;
    protected static final int KU_KEY_ENCIPHERMENT = 2;
    protected static final int KU_DATA_ENCIPHERMENT = 3;
    protected static final int KU_KEY_AGREEMENT = 4;
    protected static final int KU_KEY_CERT_SIGN = 5;
    protected static final int KU_CRL_SIGN = 6;
    protected static final int KU_ENCIPHER_ONLY = 7;
    protected static final int KU_DECIPHER_ONLY = 8;

    protected final JcaTlsCrypto crypto;
    protected final SubjectPublicKeyInfo keyInfo;

    protected DHPublicKey pubKeyDH = null;
    protected ECPublicKey pubKeyEC = null;
    protected PublicKey pubKeyRSA = null;

    public JcaTlsRawKeyCertificate(JcaTlsCrypto crypto, byte[] keyInfo)
    {
        this(crypto, SubjectPublicKeyInfo.getInstance(keyInfo));
    }

    public JcaTlsRawKeyCertificate(JcaTlsCrypto crypto, SubjectPublicKeyInfo keyInfo)
    {
        this.crypto = crypto;
        this.keyInfo = keyInfo;
    }

    /**
     * For subclasses (e.g. {@link JcaTlsCertificate}) that source the public key from elsewhere and
     * override {@link #getPublicKey()} / {@link #getSubjectPublicKeyInfo()}.
     */
    protected JcaTlsRawKeyCertificate(JcaTlsCrypto crypto)
    {
        this.crypto = crypto;
        this.keyInfo = null;
    }

    public TlsEncryptor createEncryptor(int tlsCertificateRole) throws IOException
    {
        validateKeyUsageBit(KU_KEY_ENCIPHERMENT);

        switch (tlsCertificateRole)
        {
        case TlsCertificateRole.RSA_ENCRYPTION:
        {
            this.pubKeyRSA = getPubKeyRSA();
            return new JcaTlsRSAEncryptor(crypto, pubKeyRSA);
        }
        // TODO[gmssl]
//        case TlsCertificateRole.SM2_ENCRYPTION:
//        {
//            this.pubKeyEC = getPubKeyEC();
//            return new JcaTlsSM2Encryptor(crypto, pubKeyEC);
//        }
        }

        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public TlsVerifier createVerifier(short signatureAlgorithm) throws IOException
    {
        switch (signatureAlgorithm)
        {
        case SignatureAlgorithm.ed25519:
        case SignatureAlgorithm.ed448:
        {
            int signatureScheme = SignatureScheme.from(HashAlgorithm.Intrinsic, signatureAlgorithm);
            Tls13Verifier tls13Verifier = createVerifier(signatureScheme);
            return new LegacyTls13Verifier(signatureScheme, tls13Verifier);
        }
        }

        validateKeyUsageBit(KU_DIGITAL_SIGNATURE);

        switch (signatureAlgorithm)
        {
        case SignatureAlgorithm.dsa:
            return new JcaTlsDSAVerifier(crypto, getPubKeyDSS());

        case SignatureAlgorithm.ecdsa:
            return new JcaTlsECDSAVerifier(crypto, getPubKeyEC());

        case SignatureAlgorithm.rsa:
        {
            validateRSA_PKCS1();
            return new JcaTlsRSAVerifier(crypto, getPubKeyRSA());
        }

        case SignatureAlgorithm.rsa_pss_pss_sha256:
        case SignatureAlgorithm.rsa_pss_pss_sha384:
        case SignatureAlgorithm.rsa_pss_pss_sha512:
        {
            validateRSA_PSS_PSS(signatureAlgorithm);
            int signatureScheme = SignatureScheme.from(HashAlgorithm.Intrinsic, signatureAlgorithm);
            return new JcaTlsRSAPSSVerifier(crypto, getPubKeyRSA(), signatureScheme);
        }

        case SignatureAlgorithm.rsa_pss_rsae_sha256:
        case SignatureAlgorithm.rsa_pss_rsae_sha384:
        case SignatureAlgorithm.rsa_pss_rsae_sha512:
        {
            validateRSA_PSS_RSAE();
            int signatureScheme = SignatureScheme.from(HashAlgorithm.Intrinsic, signatureAlgorithm);
            return new JcaTlsRSAPSSVerifier(crypto, getPubKeyRSA(), signatureScheme);
        }

        // TODO[RFC 9189]
        case SignatureAlgorithm.gostr34102012_256:
        case SignatureAlgorithm.gostr34102012_512:

        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public Tls13Verifier createVerifier(int signatureScheme) throws IOException
    {
        validateKeyUsageBit(KU_DIGITAL_SIGNATURE);

        switch (signatureScheme)
        {
        case SignatureScheme.ecdsa_brainpoolP256r1tls13_sha256:
        case SignatureScheme.ecdsa_brainpoolP384r1tls13_sha384:
        case SignatureScheme.ecdsa_brainpoolP512r1tls13_sha512:
        case SignatureScheme.ecdsa_secp256r1_sha256:
        case SignatureScheme.ecdsa_secp384r1_sha384:
        case SignatureScheme.ecdsa_secp521r1_sha512:
        case SignatureScheme.ecdsa_sha1:
        {
            int cryptoHashAlgorithm = SignatureScheme.getCryptoHashAlgorithm(signatureScheme);
            String digestName = crypto.getDigestName(cryptoHashAlgorithm);
            String sigName = org.bouncycastle.tls.crypto.impl.jcajce.RSAUtil.getDigestSigAlgName(digestName)
                + "WITHECDSA";

            return crypto.createTls13Verifier(sigName, null, getPubKeyEC());
        }

        case SignatureScheme.ed25519:
            return crypto.createTls13Verifier("Ed25519", null, getPubKeyEd25519());

        case SignatureScheme.ed448:
            return crypto.createTls13Verifier("Ed448", null, getPubKeyEd448());

        case SignatureScheme.rsa_pkcs1_sha1:
        case SignatureScheme.rsa_pkcs1_sha256:
        case SignatureScheme.rsa_pkcs1_sha384:
        case SignatureScheme.rsa_pkcs1_sha512:
        {
            validateRSA_PKCS1();

            int cryptoHashAlgorithm = SignatureScheme.getCryptoHashAlgorithm(signatureScheme);
            String digestName = crypto.getDigestName(cryptoHashAlgorithm);
            String sigName = org.bouncycastle.tls.crypto.impl.jcajce.RSAUtil.getDigestSigAlgName(digestName)
                + "WITHRSA";

            return crypto.createTls13Verifier(sigName, null, getPubKeyRSA());
        }

        case SignatureScheme.rsa_pss_pss_sha256:
        case SignatureScheme.rsa_pss_pss_sha384:
        case SignatureScheme.rsa_pss_pss_sha512:
        {
            validateRSA_PSS_PSS(SignatureScheme.getSignatureAlgorithm(signatureScheme));

            int cryptoHashAlgorithm = SignatureScheme.getCryptoHashAlgorithm(signatureScheme);
            String digestName = crypto.getDigestName(cryptoHashAlgorithm);
            String sigName = org.bouncycastle.tls.crypto.impl.jcajce.RSAUtil.getDigestSigAlgName(digestName)
                + "WITHRSAANDMGF1";

            // NOTE: We explicitly set them even though they should be the defaults, because providers vary
            AlgorithmParameterSpec pssSpec = org.bouncycastle.tls.crypto.impl.jcajce.RSAUtil.getPSSParameterSpec(
                cryptoHashAlgorithm, digestName, crypto.getHelper());

            return crypto.createTls13Verifier(sigName, pssSpec, getPubKeyRSA());
        }

        case SignatureScheme.rsa_pss_rsae_sha256:
        case SignatureScheme.rsa_pss_rsae_sha384:
        case SignatureScheme.rsa_pss_rsae_sha512:
        {
            validateRSA_PSS_RSAE();

            int cryptoHashAlgorithm = SignatureScheme.getCryptoHashAlgorithm(signatureScheme);
            String digestName = crypto.getDigestName(cryptoHashAlgorithm);
            String sigName = org.bouncycastle.tls.crypto.impl.jcajce.RSAUtil.getDigestSigAlgName(digestName)
                + "WITHRSAANDMGF1";

            // NOTE: We explicitly set them even though they should be the defaults, because providers vary
            AlgorithmParameterSpec pssSpec = org.bouncycastle.tls.crypto.impl.jcajce.RSAUtil.getPSSParameterSpec(
                cryptoHashAlgorithm, digestName, crypto.getHelper());

            return crypto.createTls13Verifier(sigName, pssSpec, getPubKeyRSA());
        }

        // TODO[RFC 8998]
//        case SignatureScheme.sm2sig_sm3:

        case SignatureScheme.mldsa44:
        case SignatureScheme.mldsa65:
        case SignatureScheme.mldsa87:
        {
            ASN1ObjectIdentifier mlDsaAlgOid = PQCUtil.getMLDSAObjectidentifier(signatureScheme);
            validateMLDSA(mlDsaAlgOid);

            return crypto.createTls13Verifier("ML-DSA", null, getPubKeyMLDSA());
        }

        case SignatureScheme.DRAFT_slhdsa_sha2_128s:
        case SignatureScheme.DRAFT_slhdsa_sha2_128f:
        case SignatureScheme.DRAFT_slhdsa_sha2_192s:
        case SignatureScheme.DRAFT_slhdsa_sha2_192f:
        case SignatureScheme.DRAFT_slhdsa_sha2_256s:
        case SignatureScheme.DRAFT_slhdsa_sha2_256f:
        case SignatureScheme.DRAFT_slhdsa_shake_128s:
        case SignatureScheme.DRAFT_slhdsa_shake_128f:
        case SignatureScheme.DRAFT_slhdsa_shake_192s:
        case SignatureScheme.DRAFT_slhdsa_shake_192f:
        case SignatureScheme.DRAFT_slhdsa_shake_256s:
        case SignatureScheme.DRAFT_slhdsa_shake_256f:
        {
            ASN1ObjectIdentifier slhDsaAlgOid = PQCUtil.getSLHDSAObjectidentifier(signatureScheme);
            validateSLHDSA(slhDsaAlgOid);

            return crypto.createTls13Verifier("SLH-DSA", null, getPubKeySLHDSA());
        }

        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public byte[] getEncoded() throws IOException
    {
        return keyInfo.getEncoded(ASN1Encoding.DER);
    }

    public byte[] getExtension(ASN1ObjectIdentifier extensionOID) throws IOException
    {
        return null;
    }

    public BigInteger getSerialNumber()
    {
        return null;
    }

    public String getSigAlgOID()
    {
        return null;
    }

    public ASN1Encodable getSigAlgParams() throws IOException
    {
        return null;
    }

    DHPublicKey getPubKeyDH() throws IOException
    {
        try
        {
            return (DHPublicKey)getPublicKey();
        }
        catch (ClassCastException e)
        {
            throw new TlsFatalAlert(AlertDescription.certificate_unknown, "Public key not DH", e);
        }
    }

    DSAPublicKey getPubKeyDSS() throws IOException
    {
        try
        {
            return (DSAPublicKey)getPublicKey();
        }
        catch (ClassCastException e)
        {
            throw new TlsFatalAlert(AlertDescription.certificate_unknown, "Public key not DSS", e);
        }
    }

    ECPublicKey getPubKeyEC() throws IOException
    {
        try
        {
            return (ECPublicKey)getPublicKey();
        }
        catch (ClassCastException e)
        {
            throw new TlsFatalAlert(AlertDescription.certificate_unknown, "Public key not EC", e);
        }
    }

    PublicKey getPubKeyEd25519() throws IOException
    {
        PublicKey publicKey = getPublicKey();
        if (!"Ed25519".equals(publicKey.getAlgorithm()))
        {
            // Oracle provider (Java 15+) returns the key as an EdDSA one
            if (!("EdDSA".equals(publicKey.getAlgorithm()) && publicKey.toString().indexOf("Ed25519") >= 0))
            {
                throw new TlsFatalAlert(AlertDescription.certificate_unknown, "Public key not Ed25519");
            }
        }
        return publicKey;
    }

    PublicKey getPubKeyEd448() throws IOException
    {
        PublicKey publicKey = getPublicKey();
        if (!"Ed448".equals(publicKey.getAlgorithm()))
        {
            // Oracle provider (Java 15+) returns the key as an EdDSA one
            if (!("EdDSA".equals(publicKey.getAlgorithm()) && publicKey.toString().indexOf("Ed448") >= 0))
            {
                throw new TlsFatalAlert(AlertDescription.certificate_unknown, "Public key not Ed448");
            }
        }
        return publicKey;
    }

    PublicKey getPubKeyRSA() throws IOException
    {
        // TODO[tls] How to reliably check that this is an RSA key?
        return getPublicKey();
    }

    PublicKey getPubKeyMLDSA() throws IOException
    {
        return getPublicKey();
    }

    PublicKey getPubKeySLHDSA() throws IOException
    {
        return getPublicKey();
    }

    public short getLegacySignatureAlgorithm() throws IOException
    {
        PublicKey publicKey = getPublicKey();

        if (!supportsKeyUsageBit(KU_DIGITAL_SIGNATURE))
        {
            return -1;
        }

        /*
         * RFC 5246 7.4.6. Client Certificate
         */

        /*
         * RSA public key; the certificate MUST allow the key to be used for signing with the
         * signature scheme and hash algorithm that will be employed in the certificate verify
         * message.
         */
        if (publicKey instanceof RSAPublicKey)
        {
            return SignatureAlgorithm.rsa;
        }

        /*
         * DSA public key; the certificate MUST allow the key to be used for signing with the hash
         * algorithm that will be employed in the certificate verify message.
         */
        if (publicKey instanceof DSAPublicKey)
        {
            return SignatureAlgorithm.dsa;
        }

        /*
         * ECDSA-capable public key; the certificate MUST allow the key to be used for signing with
         * the hash algorithm that will be employed in the certificate verify message; the public
         * key MUST use a curve and point format supported by the server.
         */
        if (publicKey instanceof ECPublicKey)
        {
            // TODO Check the curve and point format
            return SignatureAlgorithm.ecdsa;
        }

        return -1;
    }

    public boolean supportsSignatureAlgorithm(short signatureAlgorithm) throws IOException
    {
        if (!supportsKeyUsageBit(KU_DIGITAL_SIGNATURE))
        {
            return false;
        }

        return implSupportsSignatureAlgorithm(signatureAlgorithm);
    }

    public boolean supportsSignatureAlgorithmCA(short signatureAlgorithm) throws IOException
    {
        return implSupportsSignatureAlgorithm(signatureAlgorithm);
    }

    public TlsCertificate checkUsageInRole(int tlsCertificateRole) throws IOException
    {
        switch (tlsCertificateRole)
        {
        case TlsCertificateRole.DH:
        {
            validateKeyUsageBit(KU_KEY_AGREEMENT);
            this.pubKeyDH = getPubKeyDH();
            return this;
        }

        case TlsCertificateRole.ECDH:
        {
            validateKeyUsageBit(KU_KEY_AGREEMENT);
            this.pubKeyEC = getPubKeyEC();
            return this;
        }
        }

        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    protected boolean implSupportsSignatureAlgorithm(short signatureAlgorithm) throws IOException
    {
        PublicKey publicKey = getPublicKey();

        switch (signatureAlgorithm)
        {
        case SignatureAlgorithm.rsa:
            return supportsRSA_PKCS1()
                && publicKey instanceof RSAPublicKey;

        case SignatureAlgorithm.dsa:
            return publicKey instanceof DSAPublicKey;

        case SignatureAlgorithm.ecdsa:
        case SignatureAlgorithm.ecdsa_brainpoolP256r1tls13_sha256:
        case SignatureAlgorithm.ecdsa_brainpoolP384r1tls13_sha384:
        case SignatureAlgorithm.ecdsa_brainpoolP512r1tls13_sha512:
            return publicKey instanceof ECPublicKey;

        case SignatureAlgorithm.ed25519:
            return "Ed25519".equals(publicKey.getAlgorithm());

        case SignatureAlgorithm.ed448:
            return "Ed448".equals(publicKey.getAlgorithm());

        case SignatureAlgorithm.rsa_pss_rsae_sha256:
        case SignatureAlgorithm.rsa_pss_rsae_sha384:
        case SignatureAlgorithm.rsa_pss_rsae_sha512:
            return supportsRSA_PSS_RSAE()
                && publicKey instanceof RSAPublicKey;

        case SignatureAlgorithm.rsa_pss_pss_sha256:
        case SignatureAlgorithm.rsa_pss_pss_sha384:
        case SignatureAlgorithm.rsa_pss_pss_sha512:
            return supportsRSA_PSS_PSS(signatureAlgorithm)
                && publicKey instanceof RSAPublicKey;

        // TODO[RFC 9189]
        case SignatureAlgorithm.gostr34102012_256:
        case SignatureAlgorithm.gostr34102012_512:

        default:
            return false;
        }
    }

    protected PublicKey getPublicKey() throws IOException
    {
        try
        {
            KeyFactory keyFactory = crypto.getHelper().createKeyFactory(
                keyInfo.getAlgorithm().getAlgorithm().getId());
            return keyFactory.generatePublic(new X509EncodedKeySpec(keyInfo.getEncoded(ASN1Encoding.DER)));
        }
        catch (Exception e)
        {
            throw new TlsFatalAlert(AlertDescription.unsupported_certificate, e);
        }
    }

    protected SubjectPublicKeyInfo getSubjectPublicKeyInfo() throws IOException
    {
        return keyInfo;
    }

    protected boolean supportsKeyUsageBit(int keyUsageBit)
    {
        return true;
    }

    protected boolean supportsMLDSA(ASN1ObjectIdentifier mlDsaAlgOid)
        throws IOException
    {
        AlgorithmIdentifier pubKeyAlgID = getSubjectPublicKeyInfo().getAlgorithm();
        return PQCUtil.supportsMLDSA(pubKeyAlgID, mlDsaAlgOid);
    }

    protected boolean supportsRSA_PKCS1()
        throws IOException
    {
        AlgorithmIdentifier pubKeyAlgID = getSubjectPublicKeyInfo().getAlgorithm();
        return RSAUtil.supportsPKCS1(pubKeyAlgID);
    }

    protected boolean supportsRSA_PSS_PSS(short signatureAlgorithm)
        throws IOException
    {
        AlgorithmIdentifier pubKeyAlgID = getSubjectPublicKeyInfo().getAlgorithm();
        return RSAUtil.supportsPSS_PSS(signatureAlgorithm, pubKeyAlgID);
    }

    protected boolean supportsRSA_PSS_RSAE()
        throws IOException
    {
        AlgorithmIdentifier pubKeyAlgID = getSubjectPublicKeyInfo().getAlgorithm();
        return RSAUtil.supportsPSS_RSAE(pubKeyAlgID);
    }

    protected boolean supportsSLHDSA(ASN1ObjectIdentifier slhDsaAlgOid)
        throws IOException
    {
        AlgorithmIdentifier pubKeyAlgID = getSubjectPublicKeyInfo().getAlgorithm();
        return PQCUtil.supportsSLHDSA(pubKeyAlgID, slhDsaAlgOid);
    }

    protected void validateKeyUsageBit(int keyUsageBit)
        throws IOException
    {
        if (!supportsKeyUsageBit(keyUsageBit))
        {
            switch (keyUsageBit)
            {
            case KeyUsage.digitalSignature:
                throw new TlsFatalAlert(AlertDescription.certificate_unknown,
                    "KeyUsage does not allow digital signatures");
            case KeyUsage.keyAgreement:
                throw new TlsFatalAlert(AlertDescription.certificate_unknown,
                    "KeyUsage does not allow key agreement");
            case KeyUsage.keyEncipherment:
                throw new TlsFatalAlert(AlertDescription.certificate_unknown,
                    "KeyUsage does not allow key encipherment");
            default:
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }
    }

    protected void validateMLDSA(ASN1ObjectIdentifier mlDsaAlgOid)
        throws IOException
    {
        if (!supportsMLDSA(mlDsaAlgOid))
        {
            throw new TlsFatalAlert(AlertDescription.certificate_unknown, "No support for ML-DSA signature scheme");
        }
    }

    protected void validateRSA_PKCS1()
        throws IOException
    {
        if (!supportsRSA_PKCS1())
        {
            throw new TlsFatalAlert(AlertDescription.certificate_unknown, "No support for rsa_pkcs1 signature schemes");
        }
    }

    protected void validateRSA_PSS_PSS(short signatureAlgorithm)
        throws IOException
    {
        if (!supportsRSA_PSS_PSS(signatureAlgorithm))
        {
            throw new TlsFatalAlert(AlertDescription.certificate_unknown,
                "No support for rsa_pss_pss signature schemes");
        }
    }

    protected void validateRSA_PSS_RSAE()
        throws IOException
    {
        if (!supportsRSA_PSS_RSAE())
        {
            throw new TlsFatalAlert(AlertDescription.certificate_unknown,
                "No support for rsa_pss_rsae signature schemes");
        }
    }

    protected void validateSLHDSA(ASN1ObjectIdentifier slhDsaAlgOid)
        throws IOException
    {
        if (!supportsSLHDSA(slhDsaAlgOid))
        {
            throw new TlsFatalAlert(AlertDescription.certificate_unknown, "No support for SLH-DSA signature scheme");
        }
    }
}
