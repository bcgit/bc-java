package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.interfaces.DHPublicKey;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.Tls13Verifier;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCertificateRole;
import org.bouncycastle.tls.crypto.TlsCryptoException;
import org.bouncycastle.tls.crypto.TlsEncryptor;
import org.bouncycastle.tls.crypto.TlsVerifier;
import org.bouncycastle.tls.crypto.impl.LegacyTls13Verifier;
import org.bouncycastle.tls.crypto.impl.RSAUtil;

/**
 * Implementation class for a single X.509 certificate based on the JCA.
 */
public class JcaTlsCertificate
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

    public static JcaTlsCertificate convert(JcaTlsCrypto crypto, TlsCertificate certificate) throws IOException
    {
        if (certificate instanceof JcaTlsCertificate)
        {
            return (JcaTlsCertificate)certificate;
        }

        return new JcaTlsCertificate(crypto, certificate.getEncoded());
    }

    public static X509Certificate parseCertificate(JcaJceHelper helper, byte[] encoding)
        throws IOException
    {
        try
        {
            /*
             * NOTE: We want to restrict 'encoding' to a binary BER encoding, but
             * CertificateFactory.generateCertificate claims to require DER encoding, and also
             * supports Base64 encodings (in PEM format), which we don't support.
             * 
             * Re-encoding validates as BER and produces DER.
             */
            ASN1Primitive asn1 = TlsUtils.readASN1Object(encoding);
            byte[] derEncoding = Certificate.getInstance(asn1).getEncoded(ASN1Encoding.DER);

            ByteArrayInputStream input = new ByteArrayInputStream(derEncoding);
            X509Certificate certificate = (X509Certificate)helper.createCertificateFactory("X.509")
                .generateCertificate(input);
            if (input.available() != 0)
            {
                throw new IOException("Extra data detected in stream");
            }
            return certificate;
        }
        catch (GeneralSecurityException e)
        {
            throw new TlsCryptoException("unable to decode certificate", e);
        }
    }

    protected final JcaTlsCrypto crypto;
    protected final X509Certificate certificate;

    protected DHPublicKey pubKeyDH = null;
    protected ECPublicKey pubKeyEC = null;
    protected PublicKey pubKeyRSA = null;

    public JcaTlsCertificate(JcaTlsCrypto crypto, byte[] encoding)
        throws IOException
    {
        this(crypto, parseCertificate(crypto.getHelper(), encoding));
    }

    public JcaTlsCertificate(JcaTlsCrypto crypto, X509Certificate certificate)
    {
        this.crypto = crypto;
        this.certificate = certificate;
    }

    public TlsEncryptor createEncryptor(int tlsCertificateRole) throws IOException
    {
        validateKeyUsageBit(JcaTlsCertificate.KU_KEY_ENCIPHERMENT);

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

        throw new TlsFatalAlert(AlertDescription.certificate_unknown);
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

        default:
            throw new TlsFatalAlert(AlertDescription.certificate_unknown);
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
            AlgorithmParameterSpec pssSpec = org.bouncycastle.tls.crypto.impl.jcajce.RSAUtil
                .getPSSParameterSpec(cryptoHashAlgorithm, digestName, crypto.getHelper());

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
            AlgorithmParameterSpec pssSpec = org.bouncycastle.tls.crypto.impl.jcajce.RSAUtil
                .getPSSParameterSpec(cryptoHashAlgorithm, digestName, crypto.getHelper());

            return crypto.createTls13Verifier(sigName, pssSpec, getPubKeyRSA());
        }

        // TODO[RFC 8998]
//        case SignatureScheme.sm2sig_sm3:

        default:
            throw new TlsFatalAlert(AlertDescription.certificate_unknown);
        }
    }

    public byte[] getEncoded() throws IOException
    {
        try
        {
            // DER encoding enforced by provider - as defined by JCA for X.509 certificates.
            return certificate.getEncoded();
        }
        catch (CertificateEncodingException e)
        {
            throw new TlsCryptoException("unable to encode certificate: " + e.getMessage(), e);
        }
    }

    public byte[] getExtension(ASN1ObjectIdentifier extensionOID) throws IOException
    {
        byte[] encoding = certificate.getExtensionValue(extensionOID.getId());
        return encoding == null ? null : ((ASN1OctetString)ASN1Primitive.fromByteArray(encoding)).getOctets();
    }

    public BigInteger getSerialNumber()
    {
        return certificate.getSerialNumber();
    }

    public String getSigAlgOID()
    {
        return certificate.getSigAlgOID();
    }

    public ASN1Encodable getSigAlgParams() throws IOException
    {
        byte[] derEncoding = certificate.getSigAlgParams();
        if (null == derEncoding)
        {
            return null;
        }

        ASN1Primitive asn1 = TlsUtils.readASN1Object(derEncoding);
        // TODO[tls] Without a known ASN.1 type, this is not-quite-right
        TlsUtils.requireDEREncoding(asn1, derEncoding);
        return asn1;
    }

    DHPublicKey getPubKeyDH() throws IOException
    {
        try
        {
            return (DHPublicKey)getPublicKey();
        }
        catch (ClassCastException e)
        {
            throw new TlsFatalAlert(AlertDescription.certificate_unknown, e);
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
            throw new TlsFatalAlert(AlertDescription.certificate_unknown, e);
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
            throw new TlsFatalAlert(AlertDescription.certificate_unknown, e);
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
                throw new TlsFatalAlert(AlertDescription.certificate_unknown);
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
                throw new TlsFatalAlert(AlertDescription.certificate_unknown);
            }
        }
        return publicKey;
    }

    PublicKey getPubKeyRSA() throws IOException
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

        throw new TlsFatalAlert(AlertDescription.certificate_unknown);
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

        default:
            return false;
        }
    }

    protected PublicKey getPublicKey() throws IOException
    {
        try
        {
            return certificate.getPublicKey();
        }
        catch (RuntimeException e)
        {
            throw new TlsFatalAlert(AlertDescription.bad_certificate, e);
        }
    }

    protected SubjectPublicKeyInfo getSubjectPublicKeyInfo() throws IOException
    {
        return SubjectPublicKeyInfo.getInstance(getPublicKey().getEncoded());
    }

    public X509Certificate getX509Certificate()
    {
        return certificate;
    }

    protected boolean supportsKeyUsageBit(int keyUsageBit)
    {
        boolean[] keyUsage = certificate.getKeyUsage();

        return null == keyUsage || (keyUsage.length > keyUsageBit && keyUsage[keyUsageBit]);
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

    protected void validateKeyUsageBit(int keyUsageBit)
        throws IOException
    {
        if (!supportsKeyUsageBit(keyUsageBit))
        {
            throw new TlsFatalAlert(AlertDescription.certificate_unknown);
        }
    }

    protected void validateRSA_PKCS1()
        throws IOException
    {
        if (!supportsRSA_PKCS1())
        {
            throw new TlsFatalAlert(AlertDescription.certificate_unknown);
        }
    }

    protected void validateRSA_PSS_PSS(short signatureAlgorithm)
        throws IOException
    {
        if (!supportsRSA_PSS_PSS(signatureAlgorithm))
        {
            throw new TlsFatalAlert(AlertDescription.certificate_unknown);
        }
    }

    protected void validateRSA_PSS_RSAE()
        throws IOException
    {
        if (!supportsRSA_PSS_RSAE())
        {
            throw new TlsFatalAlert(AlertDescription.certificate_unknown);
        }
    }
}
