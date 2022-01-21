package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Signature;

/**
 * ExplicitCertificate ::= CertificateBase (WITH COMPONENTS {...,
 * type(explicit),
 * toBeSigned(WITH COMPONENTS {...,
 * verifyKeyIndicator(WITH COMPONENTS {verificationKey})
 * }),
 * signature PRESENT
 * })
 */
public class ExplicitCertificate
    extends CertificateBase
{

    private ExplicitCertificate(CertificateBase base)
    {
        this(base.getVersion(), base.getIssuer(), base.getToBeSignedCertificate(), base.getSignature());
    }

    public ExplicitCertificate(ASN1Integer version, IssuerIdentifier issuer, ToBeSignedCertificate toBeSignedCertificate, Signature signature)
    {
        super(version, CertificateType.Explicit, issuer, toBeSignedCertificate, signature);
    }

    public static ExplicitCertificate getInstance(Object o)
    {
        if (o instanceof ExplicitCertificate)
        {
            return (ExplicitCertificate)o;
        }

        CertificateBase base = CertificateBase.getInstance(o);

        if (base != null)
        {
            if (!base.getType().equals(CertificateType.Explicit))
            {
                throw new IllegalArgumentException("object was certificate base but the type was not explicit");
            }
            return new ExplicitCertificate(base);
        }

        return null;

    }

}
