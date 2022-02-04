package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
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

    public ExplicitCertificate(CertificateBase base)
    {
        this(base.getVersion(), base.getIssuer(), base.getToBeSignedCertificate(), base.getSignature());
    }

    public ExplicitCertificate(ASN1Integer version, IssuerIdentifier issuer, ToBeSignedCertificate toBeSignedCertificate, Signature signature)
    {
        super(version, CertificateType.explicit, issuer, toBeSignedCertificate, signature);
    }


    protected ExplicitCertificate(ASN1Sequence seq)
    {
        super(seq);
        if (!getType().equals(CertificateType.explicit))
        {
            throw new IllegalArgumentException("object was certificate base but the type was not explicit");
        }
    }

    public static ExplicitCertificate getInstance(Object o)
    {
        if (o instanceof ExplicitCertificate)
        {
            return (ExplicitCertificate)o;
        }

        if (o != null)
        {
            return new ExplicitCertificate(ASN1Sequence.getInstance(o));
        }

        return null;
    }

}
