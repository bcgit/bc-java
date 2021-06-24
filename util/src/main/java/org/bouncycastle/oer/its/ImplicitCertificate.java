package org.bouncycastle.oer.its;

import org.bouncycastle.asn1.ASN1Integer;

public class ImplicitCertificate
    extends CertificateBase
{
    public ImplicitCertificate(ASN1Integer version, IssuerIdentifier issuer, ToBeSignedCertificate toBeSignedCertificate, Signature signature)
    {
        super(version, CertificateType.Implicit, issuer, toBeSignedCertificate, signature);
    }
}
