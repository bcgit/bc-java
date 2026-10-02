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
 * 8 = SM4-CFB, and this type represents every one of them, so that a conformant ciphertext
 * of any mode can be parsed and inspected. Which modes are <i>implemented</i> is a separate
 * question, answered one layer up: {@code Cipher.SM9} decrypts in the stream
 * ({@link #EN_TYPE_STREAM}) and SM4-ECB ({@link #EN_TYPE_SM4}) modes and refuses a ciphertext
 * whose enType is not the one it was configured for. The value is never taken as the mode to
 * decrypt in.
 * <p>
 * C1 and C3 have a fixed size, 65 and 32 bytes, and both constructors hold them to it; C2 is
 * as long as the encapsulated message makes it.
 */
public class SM9Cipher
    extends ASN1Object
{
    /** GM/T 0080-2020 data-encapsulation type 0: the KDF-based stream cipher (XOR). */
    public static final int EN_TYPE_STREAM = 0;
    /** GM/T 0080-2020 data-encapsulation type 1: SM4 in ECB mode. */
    public static final int EN_TYPE_SM4 = 1;
    /** GM/T 0080-2020 data-encapsulation type 2: SM4 in CBC mode (not implemented by Cipher.SM9). */
    public static final int EN_TYPE_SM4_CBC = 2;
    /** GM/T 0080-2020 data-encapsulation type 4: SM4 in OFB mode (not implemented by Cipher.SM9). */
    public static final int EN_TYPE_SM4_OFB = 4;
    /** GM/T 0080-2020 data-encapsulation type 8: SM4 in CFB mode (not implemented by Cipher.SM9). */
    public static final int EN_TYPE_SM4_CFB = 8;

    private final int enType;
    private final byte[] c1;
    private final byte[] c3;
    private final byte[] c2;

    public SM9Cipher(int enType, byte[] c1, byte[] c3, byte[] c2)
    {
        // the same enType values getInstance takes, so that the type never writes an encoding it
        // would refuse to read back - it used to accept any int here
        if (!isEnType(enType))
        {
            throw new IllegalArgumentException("unknown SM9 encryption type: " + enType);
        }
        if (c1 == null || c3 == null || c2 == null)
        {
            // an absent field would otherwise surface as a NullPointerException from encoding
            throw new NullPointerException("SM9Cipher fields cannot be null");
        }
        checkLengths(c1, c3);
        this.enType = enType;
        this.c1 = Arrays.clone(c1);
        this.c3 = Arrays.clone(c3);
        this.c2 = Arrays.clone(c2);
    }

    private static boolean isEnType(int enType)
    {
        return enType == EN_TYPE_STREAM || enType == EN_TYPE_SM4
            || enType == EN_TYPE_SM4_CBC || enType == EN_TYPE_SM4_OFB || enType == EN_TYPE_SM4_CFB;
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
        int[] known = { EN_TYPE_STREAM, EN_TYPE_SM4, EN_TYPE_SM4_CBC, EN_TYPE_SM4_OFB, EN_TYPE_SM4_CFB };
        int found = -1;
        for (int i = 0; i != known.length; i++)
        {
            if (type.hasValue(known[i]))
            {
                found = known[i];
            }
        }
        if (found < 0)
        {
            throw new IllegalArgumentException("unknown SM9 encryption type");
        }
        this.enType = found;
        this.c1 = octets(ASN1BitString.getInstance(seq.getObjectAt(1)));
        this.c3 = ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets();
        this.c2 = ASN1OctetString.getInstance(seq.getObjectAt(3)).getOctets();
        checkLengths(c1, c3);
    }

    /**
     * The engine reads C1 || C3 || C2 at fixed offsets, so with the sizes unchecked a C3 a byte
     * short with C2 carrying its last byte - or a byte long carrying C2's first - decoded to
     * different fields that concatenate to the identical input, and a C1 of any other length
     * was taken as the point.
     */
    private static void checkLengths(byte[] c1, byte[] c3)
    {
        if (c1.length != 65)
        {
            throw new IllegalArgumentException("SM9 ciphertext C1 must be 65 bytes");
        }
        if (c3.length != 32)
        {
            throw new IllegalArgumentException("SM9 ciphertext C3 must be 32 bytes");
        }
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
