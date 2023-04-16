package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DEROctetString;
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

    private final int choice;
    private final ASN1Encodable publicVerificationKey;


    public PublicVerificationKey(int choice, ASN1Encodable curvePoint)
    {
        this.choice = choice;
        this.publicVerificationKey = curvePoint;
    }

    private PublicVerificationKey(ASN1TaggedObject taggedObject)
    {
        this.choice = taggedObject.getTagNo();
        switch (choice)
        {
        case ecdsaNistP256:
        case ecdsaBrainpoolP256r1:
            publicVerificationKey = EccP256CurvePoint.getInstance(taggedObject.getExplicitBaseObject());
            return;
        case ecdsaBrainpoolP384r1:
            publicVerificationKey = EccP384CurvePoint.getInstance(taggedObject.getExplicitBaseObject());
            return;
        }
        throw new IllegalArgumentException("invalid choice value " + taggedObject.getTagNo());

    }


    public static PublicVerificationKey ecdsaNistP256(EccP256CurvePoint point)
    {
        return new PublicVerificationKey(ecdsaNistP256, point);
    }

    public static PublicVerificationKey ecdsaBrainpoolP256r1(EccP256CurvePoint point)
    {
        return new PublicVerificationKey(ecdsaBrainpoolP256r1, point);
    }

    public static PublicVerificationKey ecdsaBrainpoolP384r1(EccP384CurvePoint point)
    {
        return new PublicVerificationKey(ecdsaBrainpoolP384r1, point);
    }


    public static PublicVerificationKey getInstance(Object object)
    {
        if (object instanceof PublicVerificationKey)
        {
            return (PublicVerificationKey)object;
        }

        if (object != null)
        {
            return new PublicVerificationKey(ASN1TaggedObject.getInstance(object, BERTags.CONTEXT_SPECIFIC));
        }
        return null;
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public int getChoice()
    {
        return choice;
    }

    public ASN1Encodable getPublicVerificationKey()
    {
        return publicVerificationKey;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, publicVerificationKey);
    }

    public static class Builder
    {

        private int choice;
        private ASN1Encodable curvePoint;

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

        public Builder ecdsaNistP256(EccP256CurvePoint point)
        {
            this.curvePoint = point;
            return this;
        }

        public Builder ecdsaBrainpoolP256r1(EccP256CurvePoint point)
        {
            this.curvePoint = point;
            return this;
        }

        public Builder ecdsaBrainpoolP384r1(EccP384CurvePoint point)
        {
            this.curvePoint = point;
            return this;
        }

        public Builder extension(byte[] value)
        {
            this.curvePoint = new DEROctetString(value);
            return this;
        }

        public PublicVerificationKey createPublicVerificationKey()
        {
            return new PublicVerificationKey(choice, curvePoint);
        }


    }
}
