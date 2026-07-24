package org.bouncycastle.asn1.gm;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Arrays;

/**
 * The SM9 public-key encryption ciphertext structure of GM/T 0080-2020 (the
 * C1/C2/C3 values are defined by the encryption algorithm in GM/T 0044.4).
 * <pre>
 * SM9Cipher ::= SEQUENCE {
 *     enType  INTEGER,       -- data-encapsulation type (see below)
 *     C1      BIT STRING,    -- the point C1 = [r]Q_B of G1, uncompressed (0x04||x||y)
 *     C3      OCTET STRING,  -- the MAC value C3 (32 bytes)
 *     C2      OCTET STRING   -- the encapsulated message C2
 * }
 * </pre>
 * The field order and types (enType INTEGER, C1 BIT STRING, C3/C2 OCTET STRING)
 * have been cross-checked against the GmSSL and gmsm (emmansun) reference
 * implementations of GM/T 0080-2020. The GM/T 0080-2020 data-encapsulation type
 * values are 0 = KDF stream cipher (XOR), 1 = SM4-ECB, 2 = SM4-CBC, 4 = SM4-OFB,
 * 8 = SM4-CFB; BouncyCastle implements the stream ({@link #EN_TYPE_STREAM}) and
 * SM4-ECB ({@link #EN_TYPE_SM4}) modes and rejects the others as unsupported.
 */
public class SM9Cipher
    extends ASN1Object
{
    /** GM/T 0080-2020 data-encapsulation type 0: the KDF-based stream cipher (XOR). */
    public static final int EN_TYPE_STREAM = 0;
    /** GM/T 0080-2020 data-encapsulation type 1: SM4 in ECB mode. */
    public static final int EN_TYPE_SM4 = 1;

    private final int enType;
    private final byte[] c1;
    private final byte[] c3;
    private final byte[] c2;

    public SM9Cipher(int enType, byte[] c1, byte[] c3, byte[] c2)
    {
        this.enType = enType;
        this.c1 = Arrays.clone(c1);
        this.c3 = Arrays.clone(c3);
        this.c2 = Arrays.clone(c2);
    }

    private SM9Cipher(ASN1Sequence seq)
    {
        int count = seq.size();
        if (count != 4)
        {
            throw new IllegalArgumentException("Bad sequence size: " + count);
        }
        // enType is read via hasValue rather than intValueExact so a crafted out-of-range
        // INTEGER yields a uniform IllegalArgumentException, not an ArithmeticException.
        ASN1Integer type = ASN1Integer.getInstance(seq.getObjectAt(0));
        if (type.hasValue(EN_TYPE_STREAM))
        {
            this.enType = EN_TYPE_STREAM;
        }
        else if (type.hasValue(EN_TYPE_SM4))
        {
            this.enType = EN_TYPE_SM4;
        }
        else
        {
            // GM/T 0080-2020 also defines SM4-CBC (2), SM4-OFB (4) and SM4-CFB (8), which are not implemented here.
            throw new IllegalArgumentException("unsupported SM9 encryption type (only stream and SM4-ECB are supported)");
        }
        this.c1 = octets(ASN1BitString.getInstance(seq.getObjectAt(1)));
        this.c3 = ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets();
        this.c2 = ASN1OctetString.getInstance(seq.getObjectAt(3)).getOctets();
    }

    private static byte[] octets(ASN1BitString bitString)
    {
        if (bitString.getPadBits() != 0)
        {
            throw new IllegalArgumentException("SM9 ciphertext C1 must be an octet-aligned BIT STRING");
        }
        return bitString.getOctets();
    }

    public static SM9Cipher getInstance(Object o)
    {
        if (o instanceof SM9Cipher)
        {
            return (SM9Cipher)o;
        }
        if (o != null)
        {
            return new SM9Cipher(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public int getEnType()
    {
        return enType;
    }

    public byte[] getC1()
    {
        return Arrays.clone(c1);
    }

    public byte[] getC3()
    {
        return Arrays.clone(c3);
    }

    public byte[] getC2()
    {
        return Arrays.clone(c2);
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(4);
        v.add(new ASN1Integer(enType));
        v.add(new DERBitString(c1));
        v.add(new DEROctetString(c3));
        v.add(new DEROctetString(c2));
        return new DERSequence(v);
    }
}
