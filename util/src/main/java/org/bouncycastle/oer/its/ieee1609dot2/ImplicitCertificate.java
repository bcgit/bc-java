package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Signature;

/**
 * ImplicitCertificate ::= CertificateBase (WITH COMPONENTS {...,
 * type(implicit),
 * toBeSigned(WITH COMPONENTS {...,
 * verifyKeyIndicator(WITH COMPONENTS {reconstructionValue})
 * }),
 * signature ABSENT
 * })
 */
public class ImplicitCertificate
    extends CertificateBase
{

    private ImplicitCertificate(CertificateBase base)
    {
        this(base.getVersion(), base.getIssuer(), base.getToBeSignedCertificate(), base.getSignature());
    }

    public ImplicitCertificate(ASN1Integer version, IssuerIdentifier issuer, ToBeSignedCertificate toBeSignedCertificate, Signature signature)
    {
        super(version, CertificateType.Implicit, issuer, toBeSignedCertificate, signature);
    }

    public static ImplicitCertificate getInstance(Object o)
    {
        if (o instanceof ImplicitCertificate)
        {
            return (ImplicitCertificate)o;
        }

        CertificateBase base = CertificateBase.getInstance(o);

        if (base != null)
        {
            if (!base.getType().equals(CertificateType.Implicit))
            {
                throw new IllegalArgumentException("object was certificate base but the type was not implicit");
            }
            return new ImplicitCertificate(base);
        }

        return null;

    }
}
