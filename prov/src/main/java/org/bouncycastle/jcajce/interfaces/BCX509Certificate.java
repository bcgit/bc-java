package org.bouncycastle.jcajce.interfaces;

import org.bouncycastle.asn1.x509.TBSCertificate;

public interface BCX509Certificate
{
    TBSCertificate getTBSCertificateNative();
}
