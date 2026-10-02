package org.bouncycastle.asn1.gm;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Arrays;

/**
 * The SM9 signature data structure of GM/T 0080-2020 (the (h, S) values are
 * defined by the signature algorithm in GM/T 0044.2).
 * <pre>
 * SM9Signature ::= SEQUENCE {
 *     h  OCTET STRING,   -- the integer h, 32 bytes big-endian
 *     S  BIT STRING      -- the point S of G1, uncompressed (0x04 || x || y)
 * }
 * </pre>
 * The h OCTET STRING / S BIT STRING encoding has been cross-checked against the
 * GmSSL and gmsm (emmansun) reference implementations of GM/T 0080-2020. This is
 * the structure the JCA {@code SM9} signature produces and consumes; the
 * lightweight {@link org.bouncycastle.crypto.signers.SM9Signer} works with the raw
 * h || S components, which this type wraps.
 * <p>
 * Both components have a fixed size, h 32 bytes and S 65, and both constructors hold them
 * to it.
 */
public class SM9Signature
    extends ASN1Object
{
    private final byte[] h;
    private final byte[] s;

    public SM9Signature(byte[] h, byte[] s)
    {
        if (h == null || s == null)
        {
            // an absent component would otherwise surface as a NullPointerException from encoding
            throw new NullPointerException("SM9Signature fields cannot be null");
        }
        checkLengths(h, s);
        this.h = Arrays.clone(h);
        this.s = Arrays.clone(s);
    }

    private SM9Signature(ASN1Sequence seq)
    {
        int count = seq.size();
        if (count != 2)
        {
            throw new IllegalArgumentException("Bad sequence size: " + count);
        }
        this.h = ASN1OctetString.getInstance(seq.getObjectAt(0)).getOctets();
        this.s = octets(ASN1BitString.getInstance(seq.getObjectAt(1)));
        checkLengths(h, s);
    }

    /**
     * The signer reads h || S at fixed offsets, so with the sizes unchecked two encodings that
     * divide the same 97 bytes differently between the fields - an h of 31 bytes and an S of 66,
     * say - decoded to different components that concatenate to the identical h || S, and one
     * signature had several encodings.
     */
    private static void checkLengths(byte[] h, byte[] s)
    {
        if (h.length != 32)
        {
            throw new IllegalArgumentException("SM9 signature h must be 32 bytes");
        }
        if (s.length != 65)
        {
            throw new IllegalArgumentException("SM9 signature S must be 65 bytes");
        }
    }

    private static byte[] octets(ASN1BitString bitString)
    {
        if (bitString.getPadBits() != 0)
        {
            throw new IllegalArgumentException("SM9 signature S must be an octet-aligned BIT STRING");
        }
        return bitString.getOctets();
    }

    public static SM9Signature getInstance(Object o)
    {
        if (o instanceof SM9Signature)
        {
            return (SM9Signature)o;
        }
        if (o != null)
        {
            return new SM9Signature(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public byte[] getH()
    {
        return Arrays.clone(h);
    }

    public byte[] getS()
    {
        return Arrays.clone(s);
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(new DEROctetString(h), new DERBitString(s));
    }
}
