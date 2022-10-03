package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.util.Arrays;

/**
 * Implementation class for a single X.509 certificate based on the BC light-weight API.
 */
public class BcTlsCertificate
    extends BcTlsRawKeyCertificate
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
            ASN1Primitive asn1 = TlsUtils.readASN1Object(encoding);
            return Certificate.getInstance(asn1);
        }
        catch (IllegalArgumentException e)
        {
            throw new TlsFatalAlert(AlertDescription.bad_certificate, e);
        }
    }

    protected final Certificate certificate;

    public BcTlsCertificate(BcTlsCrypto crypto, byte[] encoding)
        throws IOException
    {
        this(crypto, parseCertificate(encoding));
    }

    public BcTlsCertificate(BcTlsCrypto crypto, Certificate certificate)
    {
        super(crypto, certificate.getSubjectPublicKeyInfo());

        this.certificate = certificate;
    }

    public Certificate getCertificate()
    {
        return certificate;
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

    public ASN1Encodable getSigAlgParams()
    {
        return certificate.getSignatureAlgorithm().getParameters();
    }

    protected boolean supportsKeyUsage(int keyUsageBits)
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
                    return false;
                }
            }
        }
        return true;
    }
}
