package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

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
import org.bouncycastle.tls.ConnectionEnd;
import org.bouncycastle.tls.KeyExchangeAlgorithm;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCryptoException;
import org.bouncycastle.tls.crypto.TlsVerifier;
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
            byte[] derEncoding = Certificate.getInstance(encoding).getEncoded(ASN1Encoding.DER);

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

    public TlsVerifier createVerifier(short signatureAlgorithm) throws IOException
    {
        validateKeyUsageBit(KU_DIGITAL_SIGNATURE);

        switch (signatureAlgorithm)
        {
        case SignatureAlgorithm.rsa:
            validateRSA_PKCS1();
            return new JcaTlsRSAVerifier(crypto, getPubKeyRSA());

        case SignatureAlgorithm.dsa:
            return new JcaTlsDSAVerifier(crypto, getPubKeyDSS());

        case SignatureAlgorithm.ecdsa:
            return new JcaTlsECDSAVerifier(crypto, getPubKeyEC());

        case SignatureAlgorithm.ed25519:
            return new JcaTlsEd25519Verifier(crypto, getPubKeyEd25519());

        case SignatureAlgorithm.ed448:
            return new JcaTlsEd448Verifier(crypto, getPubKeyEd448());

        case SignatureAlgorithm.rsa_pss_rsae_sha256:
        case SignatureAlgorithm.rsa_pss_rsae_sha384:
        case SignatureAlgorithm.rsa_pss_rsae_sha512:
            validateRSA_PSS_RSAE();
            return new JcaTlsRSAPSSVerifier(crypto, getPubKeyRSA(), signatureAlgorithm);

        case SignatureAlgorithm.rsa_pss_pss_sha256:
        case SignatureAlgorithm.rsa_pss_pss_sha384:
        case SignatureAlgorithm.rsa_pss_pss_sha512:
            validateRSA_PSS_PSS(signatureAlgorithm);
            return new JcaTlsRSAPSSVerifier(crypto, getPubKeyRSA(), signatureAlgorithm);

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

        return null == derEncoding ? null : TlsUtils.readDERObject(derEncoding);
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
            throw new TlsFatalAlert(AlertDescription.certificate_unknown);
        }
        return publicKey;
    }

    PublicKey getPubKeyEd448() throws IOException
    {
        PublicKey publicKey = getPublicKey();
        if (!"Ed448".equals(publicKey.getAlgorithm()))
        {
            throw new TlsFatalAlert(AlertDescription.certificate_unknown);
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

    public TlsCertificate useInRole(int connectionEnd, int keyExchangeAlgorithm) throws IOException
    {
        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.DH_DSS:
        case KeyExchangeAlgorithm.DH_RSA:
        {
            validateKeyUsageBit(KU_KEY_AGREEMENT);
            this.pubKeyDH = getPubKeyDH();
            return this;
        }

        case KeyExchangeAlgorithm.ECDH_ECDSA:
        case KeyExchangeAlgorithm.ECDH_RSA:
        {
            validateKeyUsageBit(KU_KEY_AGREEMENT);
            this.pubKeyEC = getPubKeyEC();
            return this;
        }
        }

        if (connectionEnd == ConnectionEnd.server)
        {
            switch (keyExchangeAlgorithm)
            {
            case KeyExchangeAlgorithm.RSA:
            case KeyExchangeAlgorithm.RSA_PSK:
            {
                validateKeyUsageBit(KU_KEY_ENCIPHERMENT);
                this.pubKeyRSA = getPubKeyRSA();
                return this;
            }
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
