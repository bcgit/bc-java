package org.bouncycastle.oer.its;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.oer.OEROptional;

public class ExplicitCertificate
    extends CertificateBase
{
    public ExplicitCertificate(ASN1Integer version, IssuerIdentifier issuer, ToBeSignedCertificate toBeSignedCertificate, OEROptional signature)
    {
        super(version, CertificateType.Explicit, issuer, toBeSignedCertificate, signature);
    }

}
