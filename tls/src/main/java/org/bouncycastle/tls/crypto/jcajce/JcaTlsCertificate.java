package org.bouncycastle.tls.crypto.jcajce;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x9.DHPublicKey;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.ConnectionEnd;
import org.bouncycastle.tls.KeyExchangeAlgorithm;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.TlsDHUtils;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsVerifier;
import org.bouncycastle.tls.crypto.bc.BcTlsDSSVerifier;
import org.bouncycastle.tls.crypto.bc.BcTlsECDSAVerifier;
import org.bouncycastle.tls.crypto.bc.BcTlsRSAVerifier;

public class JcaTlsCertificate
    implements TlsCertificate
{
    private final JcaJceHelper helper;

    static JcaTlsCertificate convert(TlsCertificate certificate, JcaJceHelper helper) throws IOException
    {
        if (certificate instanceof JcaTlsCertificate)
        {
            return (JcaTlsCertificate)certificate;
        }

        return new JcaTlsCertificate(certificate.getEncoded(), helper);
    }

    protected final X509Certificate certificate;

    protected DHPublicKey pubKeyDH = null;
    protected DSAPublicKey pubKeyDSS = null;
    protected ECPublicKey pubKeyEC = null;
    protected RSAPublicKey pubKeyRSA = null;

    public JcaTlsCertificate(byte[] encoding, JcaJceHelper helper)
        throws IOException
    {
        try
        {
            this.certificate = (X509Certificate)helper.createCertificateFactory("X.509").generateCertificate(new ByteArrayInputStream(encoding));
        }
        catch (GeneralSecurityException e)
        {
            throw new IOException("unable to decode certificate: " + e.getMessage(), e);
        }
        this.helper = helper;
    }

    public TlsVerifier createVerifier(short signatureAlgorithm) throws IOException
    {
        validateKeyUsage(KeyUsage.digitalSignature);

        switch (signatureAlgorithm)
        {
        case SignatureAlgorithm.dsa:
            return null; // TODO: new BcTlsDSSVerifier(getPubKeyDSS());

        case SignatureAlgorithm.ecdsa:
            return null; // TODO: new BcTlsECDSAVerifier(getPubKeyEC());

        case SignatureAlgorithm.rsa:
            return null; // TODO: new BcTlsRSAVerifier(getPubKeyRSA());

        default:
            throw new TlsFatalAlert(AlertDescription.certificate_unknown);
        }
    }

    public byte[] getEncoded() throws IOException
    {
        try
        {
            return certificate.getEncoded();    // TODO: do we need to insist on DER here?
        }
        catch (CertificateEncodingException e)
        {
            throw new IOException("unable to encode certificate: " + e.getMessage(), e);
        }
    }

    DHPublicKey getPubKeyDH() throws IOException
    {
        DHPublicKey pubKeyDH;
        try
        {
            pubKeyDH = (DHPublicKey)getPublicKey();
        }
        catch (ClassCastException e)
        {
            throw new TlsFatalAlert(AlertDescription.certificate_unknown, e);
        }

        return validatePubKeyDH(pubKeyDH);
    }

    DSAPublicKey getPubKeyDSS() throws IOException
    {
        DSAPublicKey pubKeyDSS;
        try
        {
            pubKeyDSS = (DSAPublicKey)getPublicKey();
        }
        catch (ClassCastException e)
        {
            throw new TlsFatalAlert(AlertDescription.certificate_unknown, e);
        }

        return validatePubKeyDSS(pubKeyDSS);
    }

    ECPublicKey getPubKeyEC() throws IOException
    {
        ECPublicKey pubKeyEC;
        try
        {
            pubKeyEC = (ECPublicKey)getPublicKey();
        }
        catch (ClassCastException e)
        {
            throw new TlsFatalAlert(AlertDescription.certificate_unknown, e);
        }

        return validatePubKeyEC(pubKeyEC);
    }

    RSAPublicKey getPubKeyRSA() throws IOException
    {
        RSAPublicKey pubKeyRSA;
        try
        {
            pubKeyRSA = (RSAPublicKey)getPublicKey();
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

    protected PublicKey getPublicKey() throws IOException
    {
        try
        {
            return certificate.getPublicKey();
        }
        catch (RuntimeException e)
        {
            throw new TlsFatalAlert(AlertDescription.unsupported_certificate, e);
        }
    }

    protected void validateKeyUsage(int keyUsageBits)
        throws IOException
    {
        Extensions exts;
        try
        {
            exts = TBSCertificate.getInstance(certificate.getTBSCertificate()).getExtensions();
        }
        catch (CertificateEncodingException e)
        {
            throw new IOException("unable to parse certificate extensions: " + e.getMessage(), e);
        }

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

    protected DHPublicKey validatePubKeyDH(DHPublicKey pubKeyDH) throws IOException
    {
        return pubKeyDH; // TODO: TlsDHUtils.validateDHPublicKey(pubKeyDH);
    }

    protected DSAPublicKey validatePubKeyDSS(DSAPublicKey pubKeyDSS) throws IOException
    {
        // TODO[tls-ops]
        return pubKeyDSS;
    }

    protected ECPublicKey validatePubKeyEC(ECPublicKey pubKeyEC) throws IOException
    {
        // TODO[tls-ops]
        return pubKeyEC;
    }

    protected RSAPublicKey validatePubKeyRSA(RSAPublicKey pubKeyRSA) throws IOException
    {
        // TODO[tls-ops]
        return pubKeyRSA;
    }
}
