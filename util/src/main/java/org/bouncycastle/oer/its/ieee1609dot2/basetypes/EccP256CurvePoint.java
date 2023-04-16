package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

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
    implements ASN1Choice
{

    public static final int xonly = 0;
    public static final int fill = 1;
    public static final int compressedY0 = 2;
    public static final int compressedY1 = 3;
    public static final int uncompressedP256 = 4;


    private final int choice;
    private final ASN1Encodable eccp256CurvePoint;

    public EccP256CurvePoint(int choice, ASN1Encodable value)
    {
        this.choice = choice;
        this.eccp256CurvePoint = value;
    }

    private EccP256CurvePoint(ASN1TaggedObject ato)
    {

        choice = ato.getTagNo();
        switch (ato.getTagNo())
        {
        case fill:
            eccp256CurvePoint = ASN1Null.getInstance(ato.getExplicitBaseObject());
            break;
        case xonly:
        case compressedY0:
        case compressedY1:
            eccp256CurvePoint = ASN1OctetString.getInstance(ato.getExplicitBaseObject());
            break;
        case uncompressedP256:
            eccp256CurvePoint = Point256.getInstance(ato.getExplicitBaseObject());
            break;
        default:
            throw new IllegalArgumentException("invalid choice value " + ato.getTagNo());
        }
    }


    public static EccP256CurvePoint xOnly(ASN1OctetString value)
    {
        return new EccP256CurvePoint(xonly, value);
    }

    public static EccP256CurvePoint xOnly(byte[] value)
    {
        return new EccP256CurvePoint(xonly, new DEROctetString(Arrays.clone(value)));
    }


    public static EccP256CurvePoint fill()
    {
        return new EccP256CurvePoint(fill, DERNull.INSTANCE);
    }

    public static EccP256CurvePoint compressedY0(ASN1OctetString octetString)
    {
        return new EccP256CurvePoint(compressedY0, octetString);
    }

    public static EccP256CurvePoint compressedY1(ASN1OctetString octetString)
    {
        return new EccP256CurvePoint(compressedY1, octetString);
    }

    public static EccP256CurvePoint compressedY0(byte[] octetString)
    {
        return new EccP256CurvePoint(compressedY0, new DEROctetString(Arrays.clone(octetString)));
    }

    public static EccP256CurvePoint compressedY1(byte[] octetString)
    {
        return new EccP256CurvePoint(compressedY1, new DEROctetString(Arrays.clone(octetString)));
    }


    public static EccP256CurvePoint uncompressedP256(Point256 point256)
    {
        return new EccP256CurvePoint(uncompressedP256, point256);
    }

    public static EccP256CurvePoint uncompressedP256(BigInteger x, BigInteger y)
    {
        return new EccP256CurvePoint(uncompressedP256, Point256.builder().setX(x).setY(y).createPoint256());
    }

    public static EccP256CurvePoint createEncodedPoint(byte[] encoded)
    {
        if (encoded[0] == 0x02)
        {
            //33
            byte[] copy = new byte[encoded.length - 1];
            System.arraycopy(encoded, 1, copy, 0, copy.length);
            return new EccP256CurvePoint(compressedY0, new DEROctetString(copy));
        }
        else if (encoded[0] == 0x03)
        {
            //33
            byte[] copy = new byte[encoded.length - 1];
            System.arraycopy(encoded, 1, copy, 0, copy.length);
            return new EccP256CurvePoint(compressedY1, new DEROctetString(copy));
        }
        else if (encoded[0] == 0x04)
        {
            // 65

            return new EccP256CurvePoint(uncompressedP256,
                new Point256(new DEROctetString(Arrays.copyOfRange(encoded, 1, 34)),
                    new DEROctetString(Arrays.copyOfRange(encoded, 34, 66))));

        }
        else
        {
            throw new IllegalArgumentException("unrecognised encoding " + encoded[0]);
        }


    }


    public EccP256CurvePoint createCompressed(ECPoint point)
    {
        int choice = 0;
        byte[] encoded = point.getEncoded(true);
        if (encoded[0] == 0x02)
        {
            choice = compressedY0;
        }
        else if (encoded[0] == 0x03)
        {
            choice = compressedY1;
        }
        byte[] copy = new byte[encoded.length - 1];
        System.arraycopy(encoded, 0, copy, 0, copy.length);
        return new EccP256CurvePoint(choice, new DEROctetString(copy));
    }

    public static EccP256CurvePoint getInstance(Object object)
    {
        if (object instanceof EccP256CurvePoint)
        {
            return (EccP256CurvePoint)object;
        }

        if (object != null)
        {
            return new EccP256CurvePoint(ASN1TaggedObject.getInstance(object, BERTags.CONTEXT_SPECIFIC));
        }

        return null;
    }

    public ASN1Encodable getEccp256CurvePoint()
    {
        return eccp256CurvePoint;
    }

    public int getChoice()
    {
        return choice;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, eccp256CurvePoint);
    }

    public byte[] getEncodedPoint()
    {
        byte[] key;
        switch (choice)
        {
        case compressedY0:
        {
            byte[] originalKey = DEROctetString.getInstance(eccp256CurvePoint).getOctets();
            key = new byte[originalKey.length + 1];
            key[0] = 0x02;
            System.arraycopy(originalKey, 0, key, 1, originalKey.length);
        }
        break;
        case compressedY1:
        {
            byte[] originalKey = DEROctetString.getInstance(eccp256CurvePoint).getOctets();
            key = new byte[originalKey.length + 1];
            key[0] = 0x03;
            System.arraycopy(originalKey, 0, key, 1, originalKey.length);
        }
        break;
        case uncompressedP256:
            Point256 point256 = Point256.getInstance(eccp256CurvePoint);
            byte[] x = point256.getX().getOctets();
            byte[] y = point256.getY().getOctets();
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
