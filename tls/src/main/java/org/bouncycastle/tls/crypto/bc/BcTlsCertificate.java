package org.bouncycastle.tls.crypto.bc;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.tls.CertificateType;
import org.bouncycastle.tls.crypto.TlsCertificate;

public class BcTlsCertificate implements TlsCertificate
{
    protected Certificate certificate;

    public short getCertificateType()
    {
        return CertificateType.X509;
    }

    public byte[] getEncoded() throws IOException
    {
        return certificate.getEncoded(ASN1Encoding.DER);
    }

    public boolean hasKeyUsage(int keyUsageBits)
    {
        Extensions exts = certificate.getTBSCertificate().getExtensions();
        if (exts != null)
        {
            KeyUsage ku = KeyUsage.fromExtensions(exts);
            if (ku != null)
            {
                int bits = ku.getBytes()[0] & 0xff;
                return ((bits & keyUsageBits) == keyUsageBits);
            }
        }
        return false;
    }
}
