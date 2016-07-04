package org.bouncycastle.tls.crypto.bc;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.ConnectionEnd;
import org.bouncycastle.tls.KeyExchangeAlgorithm;
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

    protected RSAKeyParameters pubKeyRSA = null;

    public BcTlsCertificate(byte[] encoding)
    {
        this.certificate = Certificate.getInstance(encoding);
    }

    public byte[] getEncoded() throws IOException
    {
        return certificate.getEncoded(ASN1Encoding.DER);
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
        if (connectionEnd == ConnectionEnd.server && keyExchangeAlgorithm == KeyExchangeAlgorithm.RSA)
        {
            validateKeyUsage(KeyUsage.keyEncipherment);
            establishPubKeyRSA();
            return this;
        }

        // TODO[tls-ops]

        throw new UnsupportedOperationException();
    }

    protected void establishPubKeyRSA() throws IOException
    {
        SubjectPublicKeyInfo keyInfo = certificate.getSubjectPublicKeyInfo();
        RSAKeyParameters pubKeyRSA;
        try
        {
            pubKeyRSA = (RSAKeyParameters)PublicKeyFactory.createKey(keyInfo);
        }
        catch (RuntimeException e)
        {
            throw new TlsFatalAlert(AlertDescription.unsupported_certificate, e);
        }

        // Sanity check the PublicKeyFactory
        if (pubKeyRSA.isPrivate())
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        this.pubKeyRSA = validatePubKeyRSA(pubKeyRSA);
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

    protected RSAKeyParameters validatePubKeyRSA(RSAKeyParameters pubKeyRSA)
    {
        // TODO[tls-ops]
        return pubKeyRSA;
    }
}
