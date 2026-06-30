package org.bouncycastle.crypto.bls;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

/**
 * Zcash-format compressed point serialization for BLS12-381 G1 and G2,
 * matching the encoding used by Zcash, Eth2, Filecoin, and the IETF
 * pairing-friendly-curves draft.
 * <p>
 * G1 compressed encoding is 48 bytes; G2 compressed encoding is 96 bytes.
 * The high three bits of the first byte are flags:
 * <ul>
 *   <li>bit 7 (0x80): compressed (always set in this format)</li>
 *   <li>bit 6 (0x40): infinity (set iff this is the point at infinity)</li>
 *   <li>bit 5 (0x20): y-sign (set iff y &gt; -y in the encoded byte order)</li>
 * </ul>
 * Because BLS12-381 Fp is 381 bits, the x-coordinate big-endian bytes have
 * three free top bits, which is where the flag bits live. For Fp&sup2;
 * coordinates, Zcash convention orders {@code (c1, c0)} — the imaginary
 * part first.
 * <p>
 * The y-sign flag uses the lexicographic ordering of the encoded
 * {@code y} versus {@code -y}: for Fp this reduces to {@code y > (p-1)/2},
 * for Fp&sup2; to "{@code y.c1 > (p-1)/2}, or {@code y.c0 > (p-1)/2} when
 * {@code y.c1 == 0}".
 * <p>
 * Decompression validates the curve equation and the flag combinations but
 * does <em>not</em> perform a prime-order subgroup check — callers that
 * need a {@link BLS12_381BasicScheme#keyValidate validated} public key or
 * a subgroup-checked signature should do that explicitly.
 */
public class BLS12_381Serialization
{
    private static final int G1_COMPRESSED_SIZE = 48;
    private static final int G2_COMPRESSED_SIZE = 96;

    private static final int FLAG_COMPRESSED = 0x80;
    private static final int FLAG_INFINITY = 0x40;
    private static final int FLAG_SIGN = 0x20;
    private static final int FLAG_MASK = FLAG_COMPRESSED | FLAG_INFINITY | FLAG_SIGN;

    private static final BigInteger P = Fp2Element.P;
    private static final BigInteger HALF_P = P.shiftRight(1);

    private BLS12_381Serialization()
    {
    }

    /**
     * Compress a G1 point to its 48-byte Zcash-format encoding.
     */
    public static byte[] compressG1(ECPoint point)
    {
        if (point.isInfinity())
        {
            byte[] result = new byte[G1_COMPRESSED_SIZE];
            result[0] = (byte)(FLAG_COMPRESSED | FLAG_INFINITY);
            return result;
        }
        ECPoint normalised = point.normalize();
        BigInteger x = normalised.getAffineXCoord().toBigInteger();
        BigInteger y = normalised.getAffineYCoord().toBigInteger();
        byte[] result = BigIntegers.asUnsignedByteArray(G1_COMPRESSED_SIZE, x);
        int flags = FLAG_COMPRESSED | (ySignFp(y) << 5);
        result[0] |= (byte)flags;
        return result;
    }

    /**
     * Decompress a 48-byte Zcash-format encoding back to a G1 point on the
     * supplied curve. Validates the flag combinations and the curve
     * equation; does not subgroup-check.
     */
    public static ECPoint decompressG1(byte[] bytes, ECCurve curve)
    {
        if (bytes == null || bytes.length != G1_COMPRESSED_SIZE)
        {
            throw new IllegalArgumentException("G1 compressed encoding must be " + G1_COMPRESSED_SIZE + " bytes");
        }
        int flags = bytes[0] & 0xff;
        if ((flags & FLAG_COMPRESSED) == 0)
        {
            throw new IllegalArgumentException("G1 compressed flag must be set");
        }
        if ((flags & FLAG_INFINITY) != 0)
        {
            // Infinity: sign flag must be clear, x bytes (after stripping flags) must be zero.
            if ((flags & FLAG_SIGN) != 0)
            {
                throw new IllegalArgumentException("G1 infinity encoding has sign flag set");
            }
            if ((bytes[0] & ~FLAG_MASK & 0xff) != 0)
            {
                throw new IllegalArgumentException("G1 infinity encoding has non-zero x");
            }
            for (int i = 1; i < G1_COMPRESSED_SIZE; ++i)
            {
                if (bytes[i] != 0)
                {
                    throw new IllegalArgumentException("G1 infinity encoding has non-zero x");
                }
            }
            return curve.getInfinity();
        }
        int signFlag = (flags & FLAG_SIGN) != 0 ? 1 : 0;
        byte[] xBytes = new byte[G1_COMPRESSED_SIZE];
        System.arraycopy(bytes, 0, xBytes, 0, G1_COMPRESSED_SIZE);
        xBytes[0] &= (byte)~FLAG_MASK;
        BigInteger x = new BigInteger(1, xBytes);
        if (x.compareTo(P) >= 0)
        {
            throw new IllegalArgumentException("G1 x-coordinate not in [0, p)");
        }
        BigInteger ySquared = x.multiply(x).mod(P).multiply(x).mod(P)
            .add(BigInteger.valueOf(4)).mod(P);
        // p ≡ 3 (mod 4) for BLS12-381 — sqrt via modPow((p+1)/4).
        BigInteger y = ySquared.modPow(P.add(BigInteger.ONE).shiftRight(2), P);
        if (!y.multiply(y).mod(P).equals(ySquared))
        {
            throw new IllegalArgumentException("G1 x-coordinate is not on the curve");
        }
        if (ySignFp(y) != signFlag)
        {
            y = P.subtract(y);
        }
        return curve.createPoint(x, y);
    }

    /**
     * Compress a G2 point to its 96-byte Zcash-format encoding.
     */
    public static byte[] compressG2(BLS12_381G2Point point)
    {
        byte[] result = new byte[G2_COMPRESSED_SIZE];
        if (point.isInfinity())
        {
            result[0] = (byte)(FLAG_COMPRESSED | FLAG_INFINITY);
            return result;
        }
        Fp2Element x = point.x();
        Fp2Element y = point.y();
        // Zcash convention: c1 occupies bytes [0, 48), c0 occupies [48, 96).
        byte[] c1Bytes = BigIntegers.asUnsignedByteArray(G1_COMPRESSED_SIZE, x.c1());
        byte[] c0Bytes = BigIntegers.asUnsignedByteArray(G1_COMPRESSED_SIZE, x.c0());
        System.arraycopy(c1Bytes, 0, result, 0, G1_COMPRESSED_SIZE);
        System.arraycopy(c0Bytes, 0, result, G1_COMPRESSED_SIZE, G1_COMPRESSED_SIZE);
        int flags = FLAG_COMPRESSED | (ySignFp2(y) << 5);
        result[0] |= (byte)flags;
        return result;
    }

    /**
     * Decompress a 96-byte Zcash-format encoding back to a G2 point.
     * Validates the flag combinations, that the recovered x is in Fp&sup2;,
     * and that {@code (x, y)} satisfies the G2 curve equation; does not
     * subgroup-check.
     */
    public static BLS12_381G2Point decompressG2(byte[] bytes)
    {
        if (bytes == null || bytes.length != G2_COMPRESSED_SIZE)
        {
            throw new IllegalArgumentException("G2 compressed encoding must be " + G2_COMPRESSED_SIZE + " bytes");
        }
        int flags = bytes[0] & 0xff;
        if ((flags & FLAG_COMPRESSED) == 0)
        {
            throw new IllegalArgumentException("G2 compressed flag must be set");
        }
        if ((flags & FLAG_INFINITY) != 0)
        {
            if ((flags & FLAG_SIGN) != 0)
            {
                throw new IllegalArgumentException("G2 infinity encoding has sign flag set");
            }
            if ((bytes[0] & ~FLAG_MASK & 0xff) != 0)
            {
                throw new IllegalArgumentException("G2 infinity encoding has non-zero x");
            }
            for (int i = 1; i < G2_COMPRESSED_SIZE; ++i)
            {
                if (bytes[i] != 0)
                {
                    throw new IllegalArgumentException("G2 infinity encoding has non-zero x");
                }
            }
            return BLS12_381G2Point.INFINITY;
        }
        int signFlag = (flags & FLAG_SIGN) != 0 ? 1 : 0;
        byte[] c1Bytes = new byte[G1_COMPRESSED_SIZE];
        System.arraycopy(bytes, 0, c1Bytes, 0, G1_COMPRESSED_SIZE);
        c1Bytes[0] &= (byte)~FLAG_MASK;
        BigInteger xC1 = new BigInteger(1, c1Bytes);
        byte[] c0Bytes = new byte[G1_COMPRESSED_SIZE];
        System.arraycopy(bytes, G1_COMPRESSED_SIZE, c0Bytes, 0, G1_COMPRESSED_SIZE);
        BigInteger xC0 = new BigInteger(1, c0Bytes);
        if (xC0.compareTo(P) >= 0 || xC1.compareTo(P) >= 0)
        {
            throw new IllegalArgumentException("G2 x-coordinate components not in [0, p)");
        }
        Fp2Element x = Fp2Element.of(xC0, xC1);
        // y^2 = x^3 + 4*(1+I) over Fp^2.
        Fp2Element ySquared = x.square().mul(x).add(BLS12_381G2Point.B);
        Fp2Element y = ySquared.sqrtOrNull();
        if (y == null)
        {
            throw new IllegalArgumentException("G2 x-coordinate is not on the curve");
        }
        if (ySignFp2(y) != signFlag)
        {
            y = y.neg();
        }
        return BLS12_381G2Point.of(x, y);
    }

    private static int ySignFp(BigInteger y)
    {
        return y.compareTo(HALF_P) > 0 ? 1 : 0;
    }

    private static int ySignFp2(Fp2Element y)
    {
        if (y.c1().signum() != 0)
        {
            return y.c1().compareTo(HALF_P) > 0 ? 1 : 0;
        }
        return y.c0().compareTo(HALF_P) > 0 ? 1 : 0;
    }
}
