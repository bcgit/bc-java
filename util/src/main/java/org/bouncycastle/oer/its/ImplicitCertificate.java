package org.bouncycastle.oer.its;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.oer.OEROptional;

public class ImplicitCertificate
    extends CertificateBase
{
    public ImplicitCertificate(ASN1Integer version, IssuerIdentifier issuer, ToBeSignedCertificate toBeSignedCertificate, OEROptional signature)
    {
        super(version, CertificateType.Implicit, issuer, toBeSignedCertificate, signature);
    }
}
