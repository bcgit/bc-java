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
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.ClientCertificateType;
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

        case SignatureAlgorithm.rsa:
            return new BcTlsRSAVerifier(crypto, getPubKeyRSA());

        default:
            throw new TlsFatalAlert(AlertDescription.certificate_unknown);
        }
    }

    public short getClientCertificateType() throws IOException
    {
        AsymmetricKeyParameter publicKey = getPublicKey();
        if (publicKey.isPrivate())
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        try
        {
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
                validateKeyUsage(KeyUsage.digitalSignature);
                return ClientCertificateType.rsa_sign;
            }

            /*
             * DSA public key; the certificate MUST allow the key to be used for signing with the
             * hash algorithm that will be employed in the certificate verify message.
             */
            if (publicKey instanceof DSAPublicKeyParameters)
            {
                validateKeyUsage(KeyUsage.digitalSignature);
                return ClientCertificateType.dss_sign;
            }

            /*
             * ECDSA-capable public key; the certificate MUST allow the key to be used for signing
             * with the hash algorithm that will be employed in the certificate verify message; the
             * public key MUST use a curve and point format supported by the server.
             */
            if (publicKey instanceof ECPublicKeyParameters)
            {
                validateKeyUsage(KeyUsage.digitalSignature);
                // TODO Check the curve and point format
                return ClientCertificateType.ecdsa_sign;
            }

            // TODO Add support for ClientCertificateType.*_fixed_*
        }
        catch (IOException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new TlsFatalAlert(AlertDescription.unsupported_certificate, e);
        }

        throw new TlsFatalAlert(AlertDescription.unsupported_certificate);
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
        DSAPublicKeyParameters pubKeyDSS;
        try
        {
            pubKeyDSS = (DSAPublicKeyParameters)getPublicKey();
        }
        catch (ClassCastException e)
        {
            throw new TlsFatalAlert(AlertDescription.certificate_unknown, e);
        }

        return validatePubKeyDSS(pubKeyDSS);
    }

    public ECPublicKeyParameters getPubKeyEC() throws IOException
    {
        ECPublicKeyParameters pubKeyEC;
        try
        {
            pubKeyEC = (ECPublicKeyParameters)getPublicKey();
        }
        catch (ClassCastException e)
        {
            throw new TlsFatalAlert(AlertDescription.certificate_unknown, e);
        }

        return validatePubKeyEC(pubKeyEC);
    }

    public RSAKeyParameters getPubKeyRSA() throws IOException
    {
        RSAKeyParameters pubKeyRSA;
        try
        {
            pubKeyRSA = (RSAKeyParameters)getPublicKey();
        }
        catch (ClassCastException e)
        {
            throw new TlsFatalAlert(AlertDescription.certificate_unknown, e);
        }

        return validatePubKeyRSA(pubKeyRSA);
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

    protected DSAPublicKeyParameters validatePubKeyDSS(DSAPublicKeyParameters pubKeyDSS) throws IOException
    {
        // TODO[tls-ops]
        return pubKeyDSS;
    }

    protected ECPublicKeyParameters validatePubKeyEC(ECPublicKeyParameters pubKeyEC) throws IOException
    {
        // TODO[tls-ops]
        return pubKeyEC;
    }

    protected RSAKeyParameters validatePubKeyRSA(RSAKeyParameters pubKeyRSA) throws IOException
    {
        // TODO[tls-ops]
        return pubKeyRSA;
    }
}
