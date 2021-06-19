package org.bouncycastle.oer.its;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * EccP256CurvePoint ::= CHOICE {
 * x-only           OCTET STRING (SIZE (32)),
 * fill             NULL,
 * compressed-y-0   OCTET STRING (SIZE (32)),
 * compressed-y-1   OCTET STRING (SIZE (32)),
 * uncompressedP256 SEQUENCE  {
 * x OCTET STRING (SIZE (32)),
 * y OCTET STRING (SIZE (32))
 * }
 * }
 */
public class EccP256CurvePoint
    extends ASN1Object
    implements EccCurvePoint
{

    public static final int xOnly = 0;
    public static final int fill = 1;
    public static final int compressedY0 = 2;
    public static final int compressedY1 = 3;
    public static final int uncompressedP256 = 4;


    private final int choice;
    private final ASN1Encodable value;

    public EccP256CurvePoint(int choice, ASN1Encodable value)
    {
        this.choice = choice;
        this.value = value;
    }

    public static EccP256CurvePoint getInstance(Object object)
    {
        if (object instanceof EccP256CurvePoint)
        {
            return (EccP256CurvePoint)object;
        }

        ASN1TaggedObject ato = ASN1TaggedObject.getInstance(object);
        ASN1Encodable value;
        switch (ato.getTagNo())
        {
        case fill:
            value = ASN1Null.getInstance(ato.getObject());
            break;
        case xOnly:
        case compressedY0:
        case compressedY1:
            value = ASN1OctetString.getInstance(ato.getObject());
            break;
        case uncompressedP256:
            value = ASN1Sequence.getInstance(ato.getObject());
            break;
        default:
            throw new IllegalArgumentException("unknown tag " + ato.getTagNo());
        }

        return new Builder().setChoice(ato.getTagNo()).setValue(value).createEccP256CurvePoint();
    }

    public ASN1Encodable getValue()
    {
        return value;
    }

    public int getChoice()
    {
        return choice;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, value);
    }

    @Override
    public byte[] getKeyBytes()
    {
        return DEROctetString.getInstance(value).getOctets();
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

        public Builder setValue(ASN1Encodable value)
        {
            this.value = value;
            return this;
        }

        public EccP256CurvePoint createEccP256CurvePoint()
        {
            return new EccP256CurvePoint(choice, value);
        }
    }
}
