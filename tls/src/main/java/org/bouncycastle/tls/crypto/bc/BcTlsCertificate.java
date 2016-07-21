package org.bouncycastle.tls.crypto.bc;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x509.Certificate;
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
import org.bouncycastle.tls.ConnectionEnd;
import org.bouncycastle.tls.KeyExchangeAlgorithm;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.TlsDHUtils;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsVerifier;

public class BcTlsCertificate implements TlsCertificate
{
    public static BcTlsCertificate convert(TlsCertificate certificate) throws IOException
    {
        if (certificate instanceof BcTlsCertificate)
        {
            return (BcTlsCertificate)certificate;
        }

        return new BcTlsCertificate(certificate.getEncoded());
    }

    protected final Certificate certificate;

    protected DHPublicKeyParameters pubKeyDH = null;
    protected DSAPublicKeyParameters pubKeyDSS = null;
    protected ECPublicKeyParameters pubKeyEC = null;
    protected RSAKeyParameters pubKeyRSA = null;

    public BcTlsCertificate(byte[] encoding)
    {
        this.certificate = Certificate.getInstance(encoding);
    }

    public TlsVerifier createVerifier(short signatureAlgorithm) throws IOException
    {
        validateKeyUsage(KeyUsage.digitalSignature);

        switch (signatureAlgorithm)
        {
        case SignatureAlgorithm.dsa:
            return new BcTlsDSSVerifier(getPubKeyDSS());

        case SignatureAlgorithm.ecdsa:
            return new BcTlsECDSAVerifier(getPubKeyEC());

        case SignatureAlgorithm.rsa:
            return new BcTlsRSAVerifier(getPubKeyRSA());

        default:
            throw new TlsFatalAlert(AlertDescription.certificate_unknown);
        }
    }

    public byte[] getEncoded() throws IOException
    {
        return certificate.getEncoded(ASN1Encoding.DER);
    }

    protected DHPublicKeyParameters getPubKeyDH() throws IOException
    {
        DHPublicKeyParameters pubKeyDH;
        try
        {
            pubKeyDH = (DHPublicKeyParameters)getPublicKey();
        }
        catch (ClassCastException e)
        {
            throw new TlsFatalAlert(AlertDescription.certificate_unknown, e);
        }

        return validatePubKeyDH(pubKeyDH);
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
        if (connectionEnd == ConnectionEnd.client)
        {
            switch (keyExchangeAlgorithm)
            {
            }
        }
        else if (connectionEnd == ConnectionEnd.server)
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

    protected DHPublicKeyParameters validatePubKeyDH(DHPublicKeyParameters pubKeyDH) throws IOException
    {
        return TlsDHUtils.validateDHPublicKey(pubKeyDH);
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
