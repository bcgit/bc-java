package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * BasePublicEncryptionKey ::= CHOICE {
 * eciesNistP256         EccP256CurvePoint,
 * eciesBrainpoolP256r1  EccP256CurvePoint,
 * ...
 * }
 */
public class BasePublicEncryptionKey
    extends ASN1Object
    implements ASN1Choice
{
    public static final int eciesNistP256 = 0;
    public static final int eciesBrainpoolP256r1 = 1;

    private final int choice;
    private final ASN1Encodable basePublicEncryptionKey;

    private BasePublicEncryptionKey(ASN1TaggedObject dto)
    {
        choice = dto.getTagNo();
        switch (choice)
        {
        case eciesNistP256:
        case eciesBrainpoolP256r1:
            basePublicEncryptionKey = EccP256CurvePoint.getInstance(dto.getExplicitBaseObject());
            break;
        default:
            throw new IllegalArgumentException("invalid choice value " + dto.getTagNo());
        }
    }

    public BasePublicEncryptionKey(int choice, ASN1Encodable value)
    {
        this.choice = choice;
        this.basePublicEncryptionKey = value;
    }

    public static BasePublicEncryptionKey getInstance(Object objectAt)
    {
        if (objectAt instanceof BasePublicEncryptionKey)
        {
            return (BasePublicEncryptionKey)objectAt;
        }

        if (objectAt != null)
        {
            return new BasePublicEncryptionKey(ASN1TaggedObject.getInstance(objectAt, BERTags.CONTEXT_SPECIFIC));
        }
        return null;
    }

    public static BasePublicEncryptionKey eciesNistP256(EccP256CurvePoint point)
    {
        return new BasePublicEncryptionKey(eciesNistP256, point);
    }

    public static BasePublicEncryptionKey eciesBrainpoolP256r1(EccP256CurvePoint point)
    {
        return new BasePublicEncryptionKey(eciesBrainpoolP256r1, point);
    }

    public int getChoice()
    {
        return choice;
    }

    public ASN1Encodable getBasePublicEncryptionKey()
    {
        return basePublicEncryptionKey;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, basePublicEncryptionKey);
    }

    public static class Builder
    {

        private int choice;
        private ASN1Encodable value;

        public Builder setChoice(int choice)
        {
            this.choice = choice;
            return this;
        }

        public Builder setValue(EccCurvePoint value)
        {
            this.value = value;
            return this;
        }

        public BasePublicEncryptionKey createBasePublicEncryptionKey()
        {
            return new BasePublicEncryptionKey(choice, value);
        }
    }

}
