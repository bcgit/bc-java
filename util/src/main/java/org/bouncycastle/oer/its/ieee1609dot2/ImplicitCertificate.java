package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Signature;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.UINT8;

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

    public ImplicitCertificate(CertificateBase base)
    {
        this(base.getVersion(), base.getIssuer(), base.getToBeSigned(), base.getSignature());
    }

    public ImplicitCertificate(UINT8 version, IssuerIdentifier issuer, ToBeSignedCertificate toBeSignedCertificate, Signature signature)
    {
        super(version, CertificateType.implicit, issuer, toBeSignedCertificate, signature);
    }


    private ImplicitCertificate(ASN1Sequence sequence)
    {
        super(sequence);
        if (!getType().equals(CertificateType.implicit))
        {
            throw new IllegalArgumentException("object was certificate base but the type was not implicit");
        }
    }

    public static ImplicitCertificate getInstance(Object o)
    {
        if (o instanceof ImplicitCertificate)
        {
            return (ImplicitCertificate)o;
        }

        if (o != null)
        {
            return new ImplicitCertificate(ASN1Sequence.getInstance(o));
        }

        return null;

    }
}
