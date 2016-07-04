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
import org.bouncycastle.tls.TlsDHUtils;
import org.bouncycastle.tls.TlsECCUtils;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsCertificate;

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

    public byte[] getEncoded() throws IOException
    {
        return certificate.getEncoded(ASN1Encoding.DER);
    }

    public DHPublicKeyParameters getPubKeyDH() throws IOException
    {
        if (pubKeyDH == null)
        {
            // Can't use for DH unless the key was previously established by call to 'useInRole'
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return pubKeyDH;
    }

    public DSAPublicKeyParameters getPubKeyDSS() throws IOException
    {
        if (pubKeyDSS == null)
        {
            // Can't use for DSA unless the key was previously established by call to 'useInRole'
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return pubKeyDSS;
    }

    public ECPublicKeyParameters getPubKeyEC() throws IOException
    {
        if (pubKeyEC == null)
        {
            // Can't use for EC unless the key was previously established by call to 'useInRole'
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return pubKeyEC;
    }

    public RSAKeyParameters getPubKeyRSA() throws IOException
    {
        if (pubKeyRSA == null)
        {
            // Can't use for RSA unless the key was previously established by call to 'useInRole'
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return pubKeyRSA;
    }

    public TlsCertificate useInRole(int connectionEnd, int keyExchangeAlgorithm) throws IOException
    {
        // TODO[tls-ops] A better design might be to return a new (subclass) TlsCertificate instance
        // TODO[tls-ops] Record the applicable key usage and check it when the public key is used 
        // TODO[tls-ops] Check all needed combinations are handled

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
            // TODO[tls-ops] Check "the algorithm used to sign the certificate"?
            case KeyExchangeAlgorithm.DH_DSS:
            case KeyExchangeAlgorithm.DH_RSA:
            {
                validateKeyUsage(KeyUsage.keyAgreement);
                establishPubKeyDH();
                return this;
            }

            // TODO[tls-ops] Check "the algorithm used to sign the certificate"?
            case KeyExchangeAlgorithm.ECDH_ECDSA:
            case KeyExchangeAlgorithm.ECDH_RSA:
            {
                validateKeyUsage(KeyUsage.keyAgreement);
                establishPubKeyEC();
                return this;
            }

            case KeyExchangeAlgorithm.RSA:
            case KeyExchangeAlgorithm.RSA_PSK:
            {
                validateKeyUsage(KeyUsage.keyEncipherment);
                establishPubKeyRSA();
                return this;
            }

            case KeyExchangeAlgorithm.DHE_DSS:
            case KeyExchangeAlgorithm.SRP_DSS:
            {
                validateKeyUsage(KeyUsage.digitalSignature);
                establishPubKeyDSS();
                return this;
            }

            case KeyExchangeAlgorithm.ECDHE_ECDSA:
            {
                validateKeyUsage(KeyUsage.digitalSignature);
                establishPubKeyEC();
                return this;
            }

            case KeyExchangeAlgorithm.DHE_RSA:
            case KeyExchangeAlgorithm.ECDHE_RSA:
            case KeyExchangeAlgorithm.SRP_RSA:
            {
                validateKeyUsage(KeyUsage.digitalSignature);
                establishPubKeyRSA();
                return this;
            }
            }
        }

        throw new TlsFatalAlert(AlertDescription.certificate_unknown);
    }

    protected void establishPubKeyDH() throws IOException
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

        this.pubKeyDH = validatePubKeyDH(pubKeyDH);
    }

    protected void establishPubKeyDSS() throws IOException
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

        this.pubKeyDSS = validatePubKeyDSS(pubKeyDSS);
    }

    protected void establishPubKeyEC() throws IOException
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

        this.pubKeyEC = validatePubKeyEC(pubKeyEC);
    }

    protected void establishPubKeyRSA() throws IOException
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

        this.pubKeyRSA = validatePubKeyRSA(pubKeyRSA);
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
        return pubKeyDSS;
    }

    protected ECPublicKeyParameters validatePubKeyEC(ECPublicKeyParameters pubKeyEC) throws IOException
    {
        return TlsECCUtils.validateECPublicKey(pubKeyEC);
    }

    protected RSAKeyParameters validatePubKeyRSA(RSAKeyParameters pubKeyRSA) throws IOException
    {
        // TODO[tls-ops]
        return pubKeyRSA;
    }
}
