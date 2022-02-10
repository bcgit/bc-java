package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

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
    extends EccCurvePoint implements ASN1Choice
{

    public static final int xOnly = 0;
    public static final int fill = 1;
    public static final int compressedY0 = 2;
    public static final int compressedY1 = 3;
    public static final int uncompressedP384 = 4;


    private final int choice;
    private final ASN1Encodable value;

    public EccP384CurvePoint(int choice, ASN1Encodable value)
    {
        this.choice = choice;
        this.value = value;
    }

    private EccP384CurvePoint(ASN1TaggedObject ato)
    {
        choice = ato.getTagNo();
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
        case uncompressedP384:
            value = ASN1Sequence.getInstance(ato.getObject());
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
            return new EccP384CurvePoint(ASN1TaggedObject.getInstance(object));
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

    public byte[] getEncodedPoint()
    {
        byte[] key;
        switch (choice)
        {
        case compressedY0:
        {
            byte[] originalKey = DEROctetString.getInstance(value).getOctets();
            key = new byte[originalKey.length + 1];
            key[0] = 0x02;
            System.arraycopy(originalKey, 0, key, 1, originalKey.length);
        }
        break;
        case compressedY1:
        {
            byte[] originalKey = DEROctetString.getInstance(value).getOctets();
            key = new byte[originalKey.length + 1];
            key[0] = 0x03;
            System.arraycopy(originalKey, 0, key, 1, originalKey.length);
        }
        break;
        case uncompressedP384:
            ASN1Sequence sequence = ASN1Sequence.getInstance(value);
            byte[] x = DEROctetString.getInstance(sequence.getObjectAt(0)).getOctets();
            byte[] y = DEROctetString.getInstance(sequence.getObjectAt(1)).getOctets();
            key = Arrays.concatenate(new byte[]{0x04}, x, y);
            break;
        case xOnly:
            throw new IllegalStateException("x Only not implemented");
        default:
            throw new IllegalStateException("unknown point choice");
        }

        return key;

    }

    public static class Builder
    {
        private int choice;
        private ASN1Encodable value;

        Builder setChoice(int choice)
        {
            this.choice = choice;
            return this;
        }

        Builder setValue(ASN1Encodable value)
        {
            this.value = value;
            return this;
        }

        public EccP384CurvePoint createXOnly(BigInteger x)
        {
            this.choice = xOnly;
            this.value = new DEROctetString(BigIntegers.asUnsignedByteArray(x));
            return this.createEccP384CurvePoint();
        }

        public EccP384CurvePoint createFill()
        {
            this.choice = fill;
            this.value = DERNull.INSTANCE;
            return this.createEccP384CurvePoint();
        }

        public EccP384CurvePoint createCompressed(ECPoint point)
        {

            byte[] encoded = point.getEncoded(true);
            if (encoded[0] == 0x02)
            {
                this.choice = compressedY0;
            }
            else if (encoded[0] == 0x03)
            {
                this.choice = compressedY1;
            }
            byte[] copy = new byte[encoded.length - 1];
            System.arraycopy(encoded, 0, copy, 0, copy.length);
            this.value = new DEROctetString(copy);
            return this.createEccP384CurvePoint();
        }

        public EccP384CurvePoint createUncompressedP384(BigInteger x, BigInteger y)
        {
            choice = uncompressedP384;
            value = new DERSequence(new ASN1Encodable[]{
                new DEROctetString(BigIntegers.asUnsignedByteArray(48, x)),
                new DEROctetString(BigIntegers.asUnsignedByteArray(48, y)),
            });
            return this.createEccP384CurvePoint();
        }

        private EccP384CurvePoint createEccP384CurvePoint()
        {
            return new EccP384CurvePoint(choice, value);
        }
    }
}
