package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
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
    public static final int extension = 2;

    private final int choice;
    private final ASN1Encodable value;

    public VerificationKeyIndicator(int choice, ASN1Encodable value)
    {
        this.choice = choice;
        this.value = value;
    }

    private VerificationKeyIndicator(ASN1TaggedObject ato)
    {
        this.choice = ato.getTagNo();
        switch (choice)
        {
        case verificationKey:
            value = PublicVerificationKey.getInstance(ato.getObject());
            break;
        case reconstructionValue:
            value = EccP256CurvePoint.getInstance(ato.getObject());
            break;
        case extension:
            value = DEROctetString.getInstance(ato.getObject());
            break;
        default:
            throw new IllegalArgumentException("invalid choice value "+choice);

        }

    }


    public static VerificationKeyIndicator getInstance(Object src)
    {
        if (src instanceof VerificationKeyIndicator)
        {
            return (VerificationKeyIndicator)src;
        }

        if (src != null) {
            return new VerificationKeyIndicator(ASN1TaggedObject.getInstance(src));
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

    public ASN1Encodable getValue()
    {
        return value;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, value);
    }

    public static class Builder
    {

        private int choice;
        private ASN1Encodable object;

        public Builder setChoice(int choice)
        {
            this.choice = choice;
            return this;
        }

        public Builder setObject(ASN1Encodable object)
        {
            this.object = object;
            return this;
        }

        public Builder publicVerificationKey(PublicVerificationKey publicVerificationKey)
        {
            this.object = publicVerificationKey;
            this.choice = verificationKey;
            return this;
        }

        public Builder reconstructionValue(EccP256CurvePoint curvePoint)
        {
            this.object = curvePoint;
            this.choice = reconstructionValue;
            return this;
        }

        public Builder extension(byte[] value)
        {
            this.object = new DEROctetString(value);
            this.choice = extension;
            return this;
        }


        public VerificationKeyIndicator createVerificationKeyIndicator()
        {
            return new VerificationKeyIndicator(choice, object);
        }
    }
}