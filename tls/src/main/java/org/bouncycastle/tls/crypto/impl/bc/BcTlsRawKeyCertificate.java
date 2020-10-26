package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCertificateRole;
import org.bouncycastle.tls.crypto.TlsEncryptor;
import org.bouncycastle.tls.crypto.TlsVerifier;
import org.bouncycastle.tls.crypto.impl.RSAUtil;

public class BcTlsRawKeyCertificate implements TlsCertificate
{

    protected final BcTlsCrypto crypto;
    protected final SubjectPublicKeyInfo keyInfo;

    protected AsymmetricKeyParameter pubKey;

    public BcTlsRawKeyCertificate(BcTlsCrypto crypto, byte[] keyInfo)
    {
        this(crypto, SubjectPublicKeyInfo.getInstance(keyInfo));
    }

    public BcTlsRawKeyCertificate(BcTlsCrypto crypto, SubjectPublicKeyInfo keyInfo)
    {
        this.crypto = crypto;
        this.keyInfo = keyInfo;
    }

    public TlsEncryptor createEncryptor(int tlsCertificateRole) throws IOException
    {
        validateKeyUsage(KeyUsage.keyEncipherment);

        switch (tlsCertificateRole)
        {
        case TlsCertificateRole.RSA_ENCRYPTION:
        {
            return new BcTlsRSAEncryptor(crypto, getPubKeyRSA());
        }
        // TODO[gmssl]
//        case TlsCertificateRole.SM2_ENCRYPTION:
//        {
//            this.pubKeyEC = getPubKeyEC();
//            return new BcTlsSM2Encryptor(crypto, pubKeyEC);
//        }
        }

        throw new TlsFatalAlert(AlertDescription.certificate_unknown);
    }

    public TlsVerifier createVerifier(short signatureAlgorithm) throws IOException
    {
        switch (signatureAlgorithm)
        {
        case SignatureAlgorithm.rsa_pss_rsae_sha256:
        case SignatureAlgorithm.rsa_pss_rsae_sha384:
        case SignatureAlgorithm.rsa_pss_rsae_sha512:
        case SignatureAlgorithm.ed25519:
        case SignatureAlgorithm.ed448:
        case SignatureAlgorithm.rsa_pss_pss_sha256:
        case SignatureAlgorithm.rsa_pss_pss_sha384:
        case SignatureAlgorithm.rsa_pss_pss_sha512:
            return createVerifier(SignatureScheme.from(HashAlgorithm.Intrinsic, signatureAlgorithm));
        }

        validateKeyUsage(KeyUsage.digitalSignature);

        switch (signatureAlgorithm)
        {
        case SignatureAlgorithm.rsa:
            validateRSA_PKCS1();
            return new BcTlsRSAVerifier(crypto, getPubKeyRSA());

        case SignatureAlgorithm.dsa:
            return new BcTlsDSAVerifier(crypto, getPubKeyDSS());

        case SignatureAlgorithm.ecdsa:
            return new BcTlsECDSAVerifier(crypto, getPubKeyEC());

        default:
            throw new TlsFatalAlert(AlertDescription.certificate_unknown);
        }
    }

    public TlsVerifier createVerifier(int signatureScheme) throws IOException
    {
        validateKeyUsage(KeyUsage.digitalSignature);

        switch (signatureScheme)
        {
        case SignatureScheme.ecdsa_brainpoolP256r1tls13_sha256:
        case SignatureScheme.ecdsa_brainpoolP384r1tls13_sha384:
        case SignatureScheme.ecdsa_brainpoolP512r1tls13_sha512:
        case SignatureScheme.ecdsa_secp256r1_sha256:
        case SignatureScheme.ecdsa_secp384r1_sha384:
        case SignatureScheme.ecdsa_secp521r1_sha512:
        case SignatureScheme.ecdsa_sha1:
            return new BcTlsECDSA13Verifier(crypto, getPubKeyEC(), signatureScheme);

        case SignatureScheme.ed25519:
            return new BcTlsEd25519Verifier(crypto, getPubKeyEd25519());

        case SignatureScheme.ed448:
            return new BcTlsEd448Verifier(crypto, getPubKeyEd448());

        case SignatureScheme.rsa_pkcs1_sha1:
        case SignatureScheme.rsa_pkcs1_sha256:
        case SignatureScheme.rsa_pkcs1_sha384:
        case SignatureScheme.rsa_pkcs1_sha512:
        {
            validateRSA_PKCS1();
            return new BcTlsRSAVerifier(crypto, getPubKeyRSA());
        }

        case SignatureScheme.rsa_pss_pss_sha256:
        case SignatureScheme.rsa_pss_pss_sha384:
        case SignatureScheme.rsa_pss_pss_sha512:
        {
            validateRSA_PSS_PSS(SignatureScheme.getSignatureAlgorithm(signatureScheme));
            return new BcTlsRSAPSSVerifier(crypto, getPubKeyRSA(), signatureScheme);
        }

        case SignatureScheme.rsa_pss_rsae_sha256:
        case SignatureScheme.rsa_pss_rsae_sha384:
        case SignatureScheme.rsa_pss_rsae_sha512:
        {
            validateRSA_PSS_RSAE();
            return new BcTlsRSAPSSVerifier(crypto, getPubKeyRSA(), signatureScheme);
        }

        // TODO[RFC 8998]
//        case SignatureScheme.sm2sig_sm3:
//            return new BcTlsSM2Verifier(crypto, getPubKeyEC(), Strings.toByteArray("TLSv1.3+GM+Cipher+Suite"));

        default:
            throw new TlsFatalAlert(AlertDescription.certificate_unknown);
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
        return keyInfo.getAlgorithm().getAlgorithm().getId();
    }

    public ASN1Encodable getSigAlgParams()
    {
        return keyInfo.getAlgorithm().getParameters();
    }

    public short getLegacySignatureAlgorithm() throws IOException
    {
        AsymmetricKeyParameter publicKey = getPublicKey();
        if (publicKey.isPrivate())
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        if (!supportsKeyUsage(KeyUsage.digitalSignature))
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
        if (publicKey instanceof RSAKeyParameters)
        {
            return SignatureAlgorithm.rsa;
        }

        /*
         * DSA public key; the certificate MUST allow the key to be used for signing with the
         * hash algorithm that will be employed in the certificate verify message.
         */
        if (publicKey instanceof DSAPublicKeyParameters)
        {
            return SignatureAlgorithm.dsa;
        }

        /*
         * ECDSA-capable public key; the certificate MUST allow the key to be used for signing
         * with the hash algorithm that will be employed in the certificate verify message; the
         * public key MUST use a curve and point format supported by the server.
         */
        if (publicKey instanceof ECPublicKeyParameters)
        {
            // TODO Check the curve and point format
            return SignatureAlgorithm.ecdsa;
        }

        return -1;
    }

    public DHPublicKeyParameters getPubKeyDH() throws IOException
    {
        try
        {
            return (DHPublicKeyParameters)getPublicKey();
        }
        catch (ClassCastException e)
        {
            throw new TlsFatalAlert(AlertDescription.certificate_unknown, e);
        }
    }

    public DSAPublicKeyParameters getPubKeyDSS() throws IOException
    {
        try
        {
            return (DSAPublicKeyParameters)getPublicKey();
        }
        catch (ClassCastException e)
        {
            throw new TlsFatalAlert(AlertDescription.certificate_unknown, e);
        }
    }

    public ECPublicKeyParameters getPubKeyEC() throws IOException
    {
        try
        {
            return (ECPublicKeyParameters)getPublicKey();
        }
        catch (ClassCastException e)
        {
            throw new TlsFatalAlert(AlertDescription.certificate_unknown, e);
        }
    }

    public Ed25519PublicKeyParameters getPubKeyEd25519() throws IOException
    {
        try
        {
            return (Ed25519PublicKeyParameters)getPublicKey();
        }
        catch (ClassCastException e)
        {
            throw new TlsFatalAlert(AlertDescription.certificate_unknown, e);
        }
    }

    public Ed448PublicKeyParameters getPubKeyEd448() throws IOException
    {
        try
        {
            return (Ed448PublicKeyParameters)getPublicKey();
        }
        catch (ClassCastException e)
        {
            throw new TlsFatalAlert(AlertDescription.certificate_unknown, e);
        }
    }

    public RSAKeyParameters getPubKeyRSA() throws IOException
    {
        try
        {
            return (RSAKeyParameters)getPublicKey();
        }
        catch (ClassCastException e)
        {
            throw new TlsFatalAlert(AlertDescription.certificate_unknown, e);
        }
    }

    public boolean supportsSignatureAlgorithm(short signatureAlgorithm) throws IOException
    {
        return supportsSignatureAlgorithm(signatureAlgorithm, KeyUsage.digitalSignature);
    }

    public boolean supportsSignatureAlgorithmCA(short signatureAlgorithm) throws IOException
    {
        return supportsSignatureAlgorithm(signatureAlgorithm, KeyUsage.keyCertSign);
    }

    public TlsCertificate checkUsageInRole(int tlsCertificateRole) throws IOException
    {
        switch (tlsCertificateRole)
        {
        case TlsCertificateRole.DH:
        {
            validateKeyUsage(KeyUsage.keyAgreement);
            getPubKeyDH();
            return this;
        }

        case TlsCertificateRole.ECDH:
        {
            validateKeyUsage(KeyUsage.keyAgreement);
            getPubKeyEC();
            return this;
        }
        }

        throw new TlsFatalAlert(AlertDescription.certificate_unknown);
    }

    public AsymmetricKeyParameter getPublicKey() throws IOException
    {
        if (pubKey == null)
        {
            try
            {
                pubKey = PublicKeyFactory.createKey(keyInfo);
            }
            catch (RuntimeException e)
            {
                throw new TlsFatalAlert(AlertDescription.unsupported_certificate, e);
            }
        }
        return pubKey;
    }

    protected boolean supportsKeyUsage(int keyUsageBits)
    {
        return true;
    }

    protected boolean supportsRSA_PKCS1()
    {
        AlgorithmIdentifier pubKeyAlgID = keyInfo.getAlgorithm();
        return RSAUtil.supportsPKCS1(pubKeyAlgID);
    }

    protected boolean supportsRSA_PSS_PSS(short signatureAlgorithm)
    {
        AlgorithmIdentifier pubKeyAlgID = keyInfo.getAlgorithm();
        return RSAUtil.supportsPSS_PSS(signatureAlgorithm, pubKeyAlgID);
    }

    protected boolean supportsRSA_PSS_RSAE()
    {
        AlgorithmIdentifier pubKeyAlgID = keyInfo.getAlgorithm();
        return RSAUtil.supportsPSS_RSAE(pubKeyAlgID);
    }

    protected boolean supportsSignatureAlgorithm(short signatureAlgorithm, int keyUsage) throws IOException
    {
        if (!supportsKeyUsage(keyUsage))
        {
            return false;
        }

        AsymmetricKeyParameter publicKey = getPublicKey();

        switch (signatureAlgorithm)
        {
        case SignatureAlgorithm.rsa:
            return supportsRSA_PKCS1()
                && publicKey instanceof RSAKeyParameters;

        case SignatureAlgorithm.dsa:
            return publicKey instanceof DSAPublicKeyParameters;

        case SignatureAlgorithm.ecdsa:
        case SignatureAlgorithm.ecdsa_brainpoolP256r1tls13_sha256:
        case SignatureAlgorithm.ecdsa_brainpoolP384r1tls13_sha384:
        case SignatureAlgorithm.ecdsa_brainpoolP512r1tls13_sha512:
            return publicKey instanceof ECPublicKeyParameters;

        case SignatureAlgorithm.ed25519:
            return publicKey instanceof Ed25519PublicKeyParameters;

        case SignatureAlgorithm.ed448:
            return publicKey instanceof Ed448PublicKeyParameters;

        case SignatureAlgorithm.rsa_pss_rsae_sha256:
        case SignatureAlgorithm.rsa_pss_rsae_sha384:
        case SignatureAlgorithm.rsa_pss_rsae_sha512:
            return supportsRSA_PSS_RSAE()
                && publicKey instanceof RSAKeyParameters;

        case SignatureAlgorithm.rsa_pss_pss_sha256:
        case SignatureAlgorithm.rsa_pss_pss_sha384:
        case SignatureAlgorithm.rsa_pss_pss_sha512:
            return supportsRSA_PSS_PSS(signatureAlgorithm)
                && publicKey instanceof RSAKeyParameters;

        default:
            return false;
        }
    }

    public void validateKeyUsage(int keyUsageBits)
        throws IOException
    {
        if (!supportsKeyUsage(keyUsageBits))
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
