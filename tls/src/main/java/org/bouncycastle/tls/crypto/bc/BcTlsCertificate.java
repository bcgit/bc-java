package org.bouncycastle.tls.crypto.bc;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;

public class BcTlsCertificate
{
    protected Certificate certificate;

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
