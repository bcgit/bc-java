package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EccP256CurvePoint;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.PublicVerificationKey;

/**
 * <pre>
 *     VerificationKeyIndicator ::= CHOICE {
 *         verificationKey PublicVerificationKey,
 *         reconstructionValue EccP256CurvePoint,
 *         ...
 *     }
 * </pre>
 */
public class VerificationKeyIndicator
    extends ASN1Object
    implements ASN1Choice
{
    public static final int verificationKey = 0;
    public static final int reconstructionValue = 1;


    private final int choice;
    private final ASN1Encodable verificationKeyIndicator;

    public VerificationKeyIndicator(int choice, ASN1Encodable value)
    {
        this.choice = choice;
        this.verificationKeyIndicator = value;
    }

    private VerificationKeyIndicator(ASN1TaggedObject ato)
    {
        this.choice = ato.getTagNo();
        switch (choice)
        {
        case verificationKey:
            verificationKeyIndicator = PublicVerificationKey.getInstance(ato.getExplicitBaseObject());
            break;
        case reconstructionValue:
            verificationKeyIndicator = EccP256CurvePoint.getInstance(ato.getExplicitBaseObject());
            break;

        default:
            throw new IllegalArgumentException("invalid choice value " + choice);

        }

    }

    public static VerificationKeyIndicator verificationKey(PublicVerificationKey value)
    {
        return new VerificationKeyIndicator(verificationKey, value);
    }

    public static VerificationKeyIndicator reconstructionValue(EccP256CurvePoint value)
    {
        return new VerificationKeyIndicator(reconstructionValue, value);
    }

    public static VerificationKeyIndicator getInstance(Object src)
    {
        if (src instanceof VerificationKeyIndicator)
        {
            return (VerificationKeyIndicator)src;
        }

        if (src != null)
        {
            return new VerificationKeyIndicator(ASN1TaggedObject.getInstance(src, BERTags.CONTEXT_SPECIFIC));
        }

        return null;

    }


    public int getChoice()
    {
        return choice;
    }

    public ASN1Encodable getVerificationKeyIndicator()
    {
        return verificationKeyIndicator;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, verificationKeyIndicator);
    }

}
