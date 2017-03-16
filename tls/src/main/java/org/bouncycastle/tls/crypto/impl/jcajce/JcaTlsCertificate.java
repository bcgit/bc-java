package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.interfaces.DHPublicKey;

import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.ClientCertificateType;
import org.bouncycastle.tls.ConnectionEnd;
import org.bouncycastle.tls.KeyExchangeAlgorithm;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsVerifier;

/**
 * Implementation class for a single X.509 certificate based on the JCA.
 */
public class JcaTlsCertificate
    implements TlsCertificate
{
    private final JcaJceHelper helper;

    public static JcaTlsCertificate convert(TlsCertificate certificate, JcaJceHelper helper) throws IOException
    {
        if (certificate instanceof JcaTlsCertificate)
        {
            return (JcaTlsCertificate)certificate;
        }

        return new JcaTlsCertificate(certificate.getEncoded(), helper);
    }

    protected final X509Certificate certificate;

    protected DHPublicKey pubKeyDH = null;
    protected ECPublicKey pubKeyEC = null;
    protected RSAPublicKey pubKeyRSA = null;

    public JcaTlsCertificate(byte[] encoding, JcaJceHelper helper)
        throws IOException
    {
        try
        {
            ByteArrayInputStream input = new ByteArrayInputStream(encoding);
            this.certificate = (X509Certificate)helper.createCertificateFactory("X.509").generateCertificate(input);
            if (input.available() != 0)
            {
                throw new IOException("Extra data detected in stream");
            }
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
            return new JcaTlsDSAVerifier(getPubKeyDSS(), helper);

        case SignatureAlgorithm.ecdsa:
            return new JcaTlsECDSAVerifier(getPubKeyEC(), helper);

        case SignatureAlgorithm.rsa:
            return new JcaTlsRSAVerifier(getPubKeyRSA(), helper);

        default:
            throw new TlsFatalAlert(AlertDescription.certificate_unknown);
        }
    }

    public short getClientCertificateType() throws IOException
    {
         PublicKey publicKey = getPublicKey();

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
             if (publicKey instanceof RSAPublicKey)
             {
                 validateKeyUsage(KeyUsage.digitalSignature);
                 return ClientCertificateType.rsa_sign;
             }

             /*
              * DSA public key; the certificate MUST allow the key to be used for signing with the
              * hash algorithm that will be employed in the certificate verify message.
              */
             if (publicKey instanceof DSAPublicKey)
             {
                 validateKeyUsage(KeyUsage.digitalSignature);
                 return ClientCertificateType.dss_sign;
             }

             /*
              * ECDSA-capable public key; the certificate MUST allow the key to be used for signing
              * with the hash algorithm that will be employed in the certificate verify message; the
              * public key MUST use a curve and point format supported by the server.
              */
             if (publicKey instanceof ECPublicKey)
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
        try
        {
            // DER encoding enforced by provider - as defined by JCA for X.509 certificates.
            return certificate.getEncoded();
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

    public X509Certificate getX509Certificate()
    {
        return certificate;
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
