package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import java.math.BigInteger;

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
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

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
    extends EccCurvePoint
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

    private EccP256CurvePoint(ASN1TaggedObject ato)
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
        case uncompressedP256:
            value = ASN1Sequence.getInstance(ato.getObject());
            break;
        default:
            throw new IllegalArgumentException("unknown tag " + ato.getTagNo());
        }
    }

    public static EccP256CurvePoint getInstance(Object object)
    {
        if (object instanceof EccP256CurvePoint)
        {
            return (EccP256CurvePoint)object;
        }

        if (object != null)
        {
            return new EccP256CurvePoint(ASN1TaggedObject.getInstance(object));
        }

        return null;
    }

    public static Builder builder()
    {
        return new Builder();
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
        case uncompressedP256:
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

        public EccP256CurvePoint createXOnly(BigInteger x)
        {
            this.choice = xOnly;
            this.value = new DEROctetString(BigIntegers.asUnsignedByteArray(x));
            return this.createEccP256CurvePoint();
        }

        public EccP256CurvePoint createFill()
        {
            this.choice = fill;
            this.value = DERNull.INSTANCE;
            return this.createEccP256CurvePoint();
        }

        public EccP256CurvePoint createCompressedY0(BigInteger y)
        {
            this.choice = compressedY0;
            throw new IllegalStateException("not fully implemented.");
        }

        public EccP256CurvePoint createCompressedY1(BigInteger y)
        {
            this.choice = compressedY1;
            throw new IllegalStateException("not fully implemented.");
        }

        public EccP256CurvePoint createUncompressedP256(BigInteger x, BigInteger y)
        {
            choice = uncompressedP256;
            value = new DERSequence(new ASN1Encodable[]{
                new DEROctetString(BigIntegers.asUnsignedByteArray(32, x)),
                new DEROctetString(BigIntegers.asUnsignedByteArray(32, y)),
            });
            return this.createEccP256CurvePoint();
        }

        private EccP256CurvePoint createEccP256CurvePoint()
        {
            return new EccP256CurvePoint(choice, value);
        }
    }
}
