package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.util.Arrays;

/**
 * EccP384CurvePoint ::= CHOICE  {
 * x-only          OCTET STRING (SIZE (48)),
 * fill            NULL,
 * compressed-y-0  OCTET STRING (SIZE (48)),
 * compressed-y-1  OCTET STRING (SIZE (48)),
 * uncompressedP384 SEQUENCE {
 * x OCTET STRING (SIZE (48)),
 * y OCTET STRING (SIZE (48))
 * }
 * }
 */
public class EccP384CurvePoint
    extends EccCurvePoint
    implements ASN1Choice
{

    public static final int xonly = 0;
    public static final int fill = 1;
    public static final int compressedY0 = 2;
    public static final int compressedY1 = 3;
    public static final int uncompressedP384 = 4;


    private final int choice;
    private final ASN1Encodable eccP384CurvePoint;

    public EccP384CurvePoint(int choice, ASN1Encodable value)
    {
        this.choice = choice;
        this.eccP384CurvePoint = value;
    }

    private EccP384CurvePoint(ASN1TaggedObject ato)
    {
        choice = ato.getTagNo();
        switch (ato.getTagNo())
        {
        case fill:
            eccP384CurvePoint = ASN1Null.getInstance(ato.getExplicitBaseObject());
            break;
        case xonly:
        case compressedY0:
        case compressedY1:
            eccP384CurvePoint = ASN1OctetString.getInstance(ato.getExplicitBaseObject());
            break;
        case uncompressedP384:
            eccP384CurvePoint = ASN1Sequence.getInstance(ato.getExplicitBaseObject());
            break;
        default:
            throw new IllegalArgumentException("invalid choice value " + ato.getTagNo());
        }
    }

    public static EccP384CurvePoint getInstance(Object object)
    {
        if (object instanceof EccP384CurvePoint)
        {
            return (EccP384CurvePoint)object;
        }

        if (object != null)
        {
            return new EccP384CurvePoint(ASN1TaggedObject.getInstance(object, BERTags.CONTEXT_SPECIFIC));
        }

        return null;
    }


    public static EccP384CurvePoint xOnly(ASN1OctetString value)
    {
        return new EccP384CurvePoint(xonly, value);
    }

    public static EccP384CurvePoint xOnly(byte[] value)
    {
        return new EccP384CurvePoint(xonly, new DEROctetString(Arrays.clone(value)));
    }

    public static EccP384CurvePoint fill()
    {
        return new EccP384CurvePoint(fill, DERNull.INSTANCE);
    }

    public static EccP384CurvePoint compressedY0(ASN1OctetString octetString)
    {
        return new EccP384CurvePoint(compressedY0, octetString);
    }

    public static EccP384CurvePoint compressedY1(ASN1OctetString octetString)
    {
        return new EccP384CurvePoint(compressedY1, octetString);
    }

    public static EccP384CurvePoint compressedY0(byte[] octetString)
    {
        return new EccP384CurvePoint(compressedY0, new DEROctetString(Arrays.clone(octetString)));
    }

    public static EccP384CurvePoint compressedY1(byte[] octetString)
    {
        return new EccP384CurvePoint(compressedY1, new DEROctetString(Arrays.clone(octetString)));
    }

    public static EccP384CurvePoint uncompressedP384(Point384 point384)
    {
        return new EccP384CurvePoint(uncompressedP384, point384);
    }

    public int getChoice()
    {
        return choice;
    }

    public ASN1Encodable getEccP384CurvePoint()
    {
        return eccP384CurvePoint;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, eccP384CurvePoint);
    }

    public byte[] getEncodedPoint()
    {
        byte[] key;
        switch (choice)
        {
        case compressedY0:
        {
            byte[] originalKey = DEROctetString.getInstance(eccP384CurvePoint).getOctets();
            key = new byte[originalKey.length + 1];
            key[0] = 0x02;
            System.arraycopy(originalKey, 0, key, 1, originalKey.length);
        }
        break;
        case compressedY1:
        {
            byte[] originalKey = DEROctetString.getInstance(eccP384CurvePoint).getOctets();
            key = new byte[originalKey.length + 1];
            key[0] = 0x03;
            System.arraycopy(originalKey, 0, key, 1, originalKey.length);
        }
        break;
        case uncompressedP384:
            ASN1Sequence sequence = ASN1Sequence.getInstance(eccP384CurvePoint);
            byte[] x = DEROctetString.getInstance(sequence.getObjectAt(0)).getOctets();
            byte[] y = DEROctetString.getInstance(sequence.getObjectAt(1)).getOctets();
            key = Arrays.concatenate(new byte[]{0x04}, x, y);
            break;
        case xonly:
            throw new IllegalStateException("x Only not implemented");
        default:
            throw new IllegalStateException("unknown point choice");
        }

        return key;

    }

}
