package org.bouncycastle.its.asn1;

import org.bouncycastle.asn1.ASN1Sequence;

public class ExplicitCertificate
    extends CertificateBase
{
    private ExplicitCertificate(ASN1Sequence seq)
    {
        super(seq);
    }
}
