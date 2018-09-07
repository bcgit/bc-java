package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
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
import org.bouncycastle.tls.ConnectionEnd;
import org.bouncycastle.tls.KeyExchangeAlgorithm;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCryptoException;
import org.bouncycastle.tls.crypto.TlsVerifier;
import org.bouncycastle.util.Arrays;

/**
 * Implementation class for a single X.509 certificate based on the BC light-weight API.
 */
public class BcTlsCertificate
    implements TlsCertificate
{
    public static BcTlsCertificate convert(BcTlsCrypto crypto, TlsCertificate certificate)
        throws IOException
    {
        if (certificate instanceof BcTlsCertificate)
        {
            return (BcTlsCertificate)certificate;
        }

        return new BcTlsCertificate(crypto, certificate.getEncoded());
    }

    public static Certificate parseCertificate(byte[] encoding)
        throws IOException
    {
        try
        {
            return Certificate.getInstance(encoding);
        }
        catch (IllegalArgumentException e)
        {
            throw new TlsCryptoException("unable to decode certificate: " + e.getMessage(), e);
        }
    }

    protected final BcTlsCrypto crypto;
    protected final Certificate certificate;

    protected DHPublicKeyParameters pubKeyDH = null;
    protected ECPublicKeyParameters pubKeyEC = null;
    protected Ed25519PublicKeyParameters pubKeyEd25519 = null;
    protected Ed448PublicKeyParameters pubKeyEd448 = null;
    protected RSAKeyParameters pubKeyRSA = null;

    public BcTlsCertificate(BcTlsCrypto crypto, byte[] encoding)
        throws IOException
    {
        this(crypto, parseCertificate(encoding));
    }

    public BcTlsCertificate(BcTlsCrypto crypto, Certificate certificate)
    {
        this.crypto = crypto;
        this.certificate = certificate;
    }

    public TlsVerifier createVerifier(short signatureAlgorithm) throws IOException
    {
        validateKeyUsage(KeyUsage.digitalSignature);

        switch (signatureAlgorithm)
        {
        case SignatureAlgorithm.dsa:
            return new BcTlsDSAVerifier(crypto, getPubKeyDSS());

        case SignatureAlgorithm.ecdsa:
            return new BcTlsECDSAVerifier(crypto, getPubKeyEC());

        case SignatureAlgorithm.ed25519:
            return new BcTlsEd25519Verifier(crypto, getPubKeyEd25519());

        case SignatureAlgorithm.ed448:
            return new BcTlsEd448Verifier(crypto, getPubKeyEd448());

        case SignatureAlgorithm.rsa:
            return new BcTlsRSAVerifier(crypto, getPubKeyRSA());

        default:
            throw new TlsFatalAlert(AlertDescription.certificate_unknown);
        }
    }

    public byte[] getEncoded() throws IOException
    {
        return certificate.getEncoded(ASN1Encoding.DER);
    }

    public byte[] getExtension(ASN1ObjectIdentifier extensionOID) throws IOException
    {
        Extensions extensions = certificate.getTBSCertificate().getExtensions();
        if (extensions != null)
        {
            Extension extension = extensions.getExtension(extensionOID);
            if (extension != null)
            {
                return Arrays.clone(extension.getExtnValue().getOctets());
            }
        }
        return null;
    }

    public BigInteger getSerialNumber()
    {
        return certificate.getSerialNumber().getValue();
    }

    public String getSigAlgOID()
    {
        return certificate.getSignatureAlgorithm().getAlgorithm().getId();
    }

    public short getSignatureAlgorithm() throws IOException
    {
        AsymmetricKeyParameter publicKey = getPublicKey();
        if (publicKey.isPrivate())
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        try
        {
            validateKeyUsage(KeyUsage.digitalSignature);
        }
        catch (IOException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new TlsFatalAlert(AlertDescription.unsupported_certificate, e);
        }

        /*
         * TODO RFC 5246 7.4.6. The certificates MUST be signed using an acceptable hash/
         * signature algorithm pair, as described in Section 7.4.4. Note that this relaxes the
         * constraints on certificate-signing algorithms found in prior versions of TLS.
         */

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

        /*
         * Ed25519 public key; the certificate MUST allow the key to be used for signing
         */
        if (publicKey instanceof Ed25519PublicKeyParameters)
        {
            return SignatureAlgorithm.ed25519;
        }

        /*
         * Ed448 public key; the certificate MUST allow the key to be used for signing
         */
        if (publicKey instanceof Ed448PublicKeyParameters)
        {
            return SignatureAlgorithm.ed448;
        }

        throw new TlsFatalAlert(AlertDescription.unsupported_certificate);
    }

    protected DHPublicKeyParameters getPubKeyDH() throws IOException
    {
        try
        {
            return (DHPublicKeyParameters)getPublicKey();
        }
        catch (RuntimeException e)
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

    public TlsCertificate useInRole(int connectionEnd, int keyExchangeAlgorithm) throws IOException
    {
        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.DH_DSS:
        case KeyExchangeAlgorithm.DH_RSA:
        {
            validateKeyUsage(KeyUsage.keyAgreement);
            this.pubKeyDH = getPubKeyDH();
            return this;
        }

        case KeyExchangeAlgorithm.ECDH_ECDSA:
        case KeyExchangeAlgorithm.ECDH_RSA:
        {
            validateKeyUsage(KeyUsage.keyAgreement);
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
                validateKeyUsage(KeyUsage.keyEncipherment);
                this.pubKeyRSA = getPubKeyRSA();
                return this;
            }
            }
        }

        throw new TlsFatalAlert(AlertDescription.certificate_unknown);
    }

    protected AsymmetricKeyParameter getPublicKey() throws IOException
    {
        SubjectPublicKeyInfo keyInfo = certificate.getSubjectPublicKeyInfo();
        try
        {
            return PublicKeyFactory.createKey(keyInfo);
        }
        catch (RuntimeException e)
        {
            throw new TlsFatalAlert(AlertDescription.unsupported_certificate, e);
        }
    }

    protected void validateKeyUsage(int keyUsageBits)
        throws IOException
    {
        Extensions exts = certificate.getTBSCertificate().getExtensions();
        if (exts != null)
        {
            KeyUsage ku = KeyUsage.fromExtensions(exts);
            if (ku != null)
            {
                int bits = ku.getBytes()[0] & 0xff;
                if ((bits & keyUsageBits) != keyUsageBits)
                {
                    throw new TlsFatalAlert(AlertDescription.certificate_unknown);
                }
            }
        }
    }
}
