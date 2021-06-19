package org.bouncycastle.oer.its;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * PublicVerificationKey ::= CHOICE {
 * ecdsaNistP256         EccP256CurvePoint,
 * ecdsaBrainpoolP256r1  EccP256CurvePoint,
 * ...,
 * ecdsaBrainpoolP384r1  EccP384CurvePoint
 * }
 */
public class PublicVerificationKey
    extends ASN1Object
    implements ASN1Choice
{

    public final static int ecdsaNistP256 = 0;
    public final static int ecdsaBrainpoolP256r1 = 1;
    public final static int ecdsaBrainpoolP384r1 = 2;

    final int choice;
    final EccCurvePoint curvePoint;


    public PublicVerificationKey(int choice, EccCurvePoint curvePoint)
    {
        this.choice = choice;
        this.curvePoint = curvePoint;
    }

    public static PublicVerificationKey getInstance(Object object)
    {

        if (object instanceof PublicVerificationKey)
        {
            return (PublicVerificationKey)object;
        }

        ASN1TaggedObject taggedObject = ASN1TaggedObject.getInstance(object);
        EccCurvePoint point;
        switch (taggedObject.getTagNo())
        {
        case ecdsaNistP256:
        case ecdsaBrainpoolP256r1:
            point = EccP256CurvePoint.getInstance(taggedObject.getObject());
            break;
        case ecdsaBrainpoolP384r1:
            point = EccP384CurvePoint.getInstance(taggedObject.getObject());
            break;
        default:
            throw new IllegalArgumentException("unknown tag value " + taggedObject.getTagNo());
        }
        return new Builder().setChoice(taggedObject.getTagNo()).setCurvePoint(point).createPublicVerificationKey();
    }


    public int getChoice()
    {
        return choice;
    }

    public EccCurvePoint getCurvePoint()
    {
        return curvePoint;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, curvePoint);
    }


    public static class Builder
    {

        private int choice;
        private EccCurvePoint curvePoint;

        public Builder setChoice(int choice)
        {
            this.choice = choice;
            return this;
        }

        public Builder setCurvePoint(EccCurvePoint curvePoint)
        {
            this.curvePoint = curvePoint;
            return this;
        }

        public PublicVerificationKey createPublicVerificationKey()
        {
            return new PublicVerificationKey(choice, curvePoint);
        }
    }
}
