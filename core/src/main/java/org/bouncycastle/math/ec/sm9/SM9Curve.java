package org.bouncycastle.math.ec.sm9;

import java.math.BigInteger;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.GLVMultiplier;
import org.bouncycastle.math.ec.custom.gm.SM9P256V1Curve;
import org.bouncycastle.math.ec.endo.GLVTypeBEndomorphism;
import org.bouncycastle.math.ec.endo.GLVTypeBParameters;
import org.bouncycastle.math.ec.endo.ScalarSplitParameters;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Pack;

/**
 * Fixed system parameters of the SM9 256-bit BN curve (GM/T 0044.5-2016, clause 1).
 * <p>
 * Curve E: y^2 = x^3 + 5 over F_q. G1 is E(F_q) itself, with generator P1 - the curve has
 * prime order N, so its cofactor is 1 and every point on it other than infinity is in G1; G2
 * is the order-N subgroup of the sextic twist E'(F_p2): y^2 = x^3 + 5u, with generator P2,
 * whose cofactor is not 1 (see {@link SM9G2Point#isInSubgroup()}). The R-ate pairing
 * e: G1 x G2 -&gt; G_T uses loop parameter 6t+2.
 */
public class SM9Curve
{

    // BN parameter t and the R-ate Miller loop constant 6t+2 (GM/T 0044.5).
    static final BigInteger T = new BigInteger("600000000058F98A", 16);
    static final BigInteger LOOP = T.multiply(BigInteger.valueOf(6)).add(BigInteger.valueOf(2));

    // G1: E: y^2 = x^3 + 5 over F_q, backed by the constant-time Montgomery custom
    // curve (fixed-limb Nat256 field) rather than the generic BigInteger ECCurve.Fp.
    public static final ECCurve G1 = new SM9P256V1Curve();

    /**
     * The group order N, shared by G1, G2 and G_T. Taken from the G1 curve, which already carries
     * it as its order, rather than transcribed a second time - two hand-copied hex strings had
     * nothing to keep them the same.
     */
    public static final BigInteger N = G1.getOrder();

    public static final ECPoint P1 = G1.createPoint(
        new BigInteger("93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD", 16),
        new BigInteger("21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616", 16));

    // G2 generator P2. Each F_p2 coordinate is (constant, u-coefficient); the
    // standard prints the u-coefficient (high dim) first.
    public static final SM9G2Point P2 = new SM9G2Point(
        new Fp2(new BigInteger("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B", 16),
                new BigInteger("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141", 16)),
        new Fp2(new BigInteger("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7", 16),
                new BigInteger("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96", 16)));

    /**
     * The width in bits of every scalar and exponent {@link #blind} returns: its top bit, bit 319,
     * is always set.
     */
    static final int BLINDED_BITS = 320;

    private static final long M = 0xFFFFFFFFL;

    // ceil(2^319 / N), the smallest multiplier of N that reaches 2^319, which is below 2^64, as
    // 32-bit words, least significant first
    private static final int[] BLIND_BASE = Nat.fromBigInteger(64,
        BigInteger.ONE.shiftLeft(BLINDED_BITS - 1).add(N).subtract(BigInteger.ONE).divide(N));

    // N as 32-bit words, least significant first, which blind adds r times
    private static final int[] N_WORDS = Nat.fromBigInteger(256, N);

    /**
     * k + r*N for a fresh random r, as the {@link #BLINDED_BITS} bits of ten 32-bit words, least
     * significant first, for the exponentiation and the multiplications that raise to or multiply
     * by a secret, {@link Fp12#powSecureFixedBase}, {@link SM9G2Point#multiply},
     * {@link #multiplySecure} and {@link #sumOfTwoMultipliesSecure}. Every element they apply it to
     * has order dividing N, so the result stands for k. ({@link Fp12#powSecure}, which splits its
     * exponent into four through the Frobenius, would split k + r*N as it splits k, and blinds the
     * split instead.)
     * <p>
     * r is drawn from [ceil(2^319 / N), ceil(2^319 / N) + 2^63), which puts k + r*N in
     * [2^319, 2^320) for every k below 2^256: N is about 0.71 * 2^256, so the largest r gives less
     * than 1.72 * 2^319. The blinded value therefore always has exactly {@link #BLINDED_BITS} bits,
     * and each runs over it the same number of steps from the same leading bit whatever k is,
     * where a draw that only pinned r's own top bit left the blinded value's leading bit at 318 or
     * 319, depending on r. The sum is formed on the fixed-width words, in the same steps whatever k
     * is, where BigInteger's addition carried through as many words as the carry reached.
     */
    static int[] blind(BigInteger k)
    {
        byte[] sBytes = new byte[8];
        CryptoServicesRegistrar.getSecureRandom().nextBytes(sBytes);
        sBytes[0] &= 0x7F;

        // r = ceil(2^319 / N) + s for the draw s, in three words, the third 0 or 1
        long c = (BLIND_BASE[0] & M) + (Pack.bigEndianToInt(sBytes, 4) & M);
        long r0 = c & M;
        c = (c >>> 32) + (BLIND_BASE[1] & M) + (Pack.bigEndianToInt(sBytes, 0) & M);
        long[] r = { r0, c & M, c >>> 32 };
        Arrays.clear(sBytes);

        int[] z = Nat.fromBigInteger(BLINDED_BITS, k);
        for (int j = 0; j < r.length; ++j)
        {
            // z += r_j N 2^(32j)
            c = 0;
            for (int i = 0; i < N_WORDS.length; ++i)
            {
                c += (z[i + j] & M) + r[j] * (N_WORDS[i] & M);
                z[i + j] = (int)c;
                c >>>= 32;
            }
            for (int i = j + N_WORDS.length; i < z.length; ++i)
            {
                c += z[i] & M;
                z[i] = (int)c;
                c >>>= 32;
            }
        }
        // r is erased as sBytes is: with the blinded value, which the callers erase, it gives k
        Arrays.clear(r);
        return z;
    }

    // the combs that take a secret blinded by blind - SM9G1Multiplier's, SM9G2Point's for P2 and
    // Fp12.powSecureFixedBase's - read it in COMB_SPACING columns of COMB_TEETH bits, spaced
    // COMB_SPACING apart - the BLINDED_BITS bits exactly - each from a table of COMB_ENTRIES entries
    static final int COMB_TEETH = 5;
    static final int COMB_SPACING = BLINDED_BITS / COMB_TEETH;
    static final int COMB_ENTRIES = 1 << COMB_TEETH;

    // 2^64 - 1 in ten 32-bit words, least significant first: the multiple, or the exponent, that the 1
    // in each entry of a comb's table adds up to over the sixty-four columns
    static final int[] COMB_OFFSET = Nat.fromBigInteger(BLINDED_BITS,
        BigInteger.ONE.shiftLeft(COMB_SPACING).subtract(BigInteger.ONE));

    // column c of a comb over k: bits c, c + 64, c + 128, c + 192 and c + 256, as the index of a table
    // entry
    static int combColumn(int[] k, int c)
    {
        int d = 0;
        for (int i = COMB_TEETH - 1; i >= 0; --i)
        {
            int bit = c + i * COMB_SPACING;
            d = (d << 1) | ((k[bit >>> 5] >>> (bit & 31)) & 1);
        }
        return d;
    }

    /**
     * Encode a G1 point as x || y (32 bytes each, big-endian), the affine-coordinate
     * form SM9 concatenates into KDF/MAC inputs and ciphertexts (no 0x04 prefix).
     */
    public static byte[] g1ToBytes(ECPoint p)
    {
        ECPoint n = p.normalize();
        return Arrays.concatenate(
            BigIntegers.asUnsignedByteArray(32, n.getAffineXCoord().toBigInteger()),
            BigIntegers.asUnsignedByteArray(32, n.getAffineYCoord().toBigInteger()));
    }

    /**
     * Reconstruct a G1 point from its 64-byte x || y encoding at {@code off}. The caller is
     * responsible for validating the result (e.g. {@link ECPoint#isValid()}).
     *
     * @throws IllegalArgumentException if fewer than 64 bytes are available at {@code off}, or
     * a coordinate is not below q.
     */
    public static ECPoint g1FromBytes(byte[] b, int off)
    {
        if (off < 0 || b.length - off < 64)
        {
            // Arrays.copyOfRange pads a range running past the end with zeros, so a short input
            // decoded to coordinates it did not contain, and an offset outside it escaped as an
            // index exception - from a decoder that otherwise reports malformed input this way
            throw new IllegalArgumentException("invalid SM9 G1 point encoding");
        }
        if (notBelowQ(b, off) || notBelowQ(b, off + 32))
        {
            // refused in the decoder's words, where the field element's own message named an
            // internal class
            throw new IllegalArgumentException("invalid SM9 G1 point encoding");
        }
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(b, off, off + 32));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(b, off + 32, off + 64));
        return G1.createPoint(x, y);
    }

    // whether the 32 bytes at off, read big-endian, are at or above q, which no coordinate is
    private static boolean notBelowQ(byte[] b, int off)
    {
        return new BigInteger(1, Arrays.copyOfRange(b, off, off + 32))
            .compareTo(G1.getField().getCharacteristic()) >= 0;
    }

    /**
     * Constant-time G1 scalar multiplication by a <b>secret</b> scalar, for a point that is
     * multiplied by many: the generator P1, which the KGC multiplies by the encryption master
     * secret and by each signing key's t2, and a user's signing key ds, which each signature
     * multiplies by its l. It runs Lim and Lee's comb over a table of thirty-two multiples of the
     * point and their doubles, 4 KB, which is made the first time the point is multiplied and kept
     * with it, so that later multiplications of the same point skip it. The comb reads the scalar
     * blinded with a random multiple of N into 320 bits, carries the entries it reads by a random
     * factor drawn for the call, reads each entry by a full scan of the table from an entry drawn at
     * random, and takes the running point at infinity or equal to the entry it adds by the same steps
     * as any other - the entry itself, or its double, which the table holds beside it - so that
     * neither the steps it takes, the memory it reads nor the values it computes on follow the
     * scalar's digits from call to call.
     * <p>
     * NOTE: the multiplication computes in F_q on fixed-width limbs in Montgomery form, as the
     * pairing does and as G1's field {@link org.bouncycastle.math.ec.custom.gm.SM9P256V1Field}
     * does, in arithmetic that runs the same instructions whatever values it is given - its
     * reduction below q included, which BouncyCastle's other custom prime-field curves make by a
     * conditional subtraction.
     * <p>
     * The result is checked to lie on the curve, as BouncyCastle's multipliers check theirs, and one
     * that does not - a fault in the table kept with the point, or in the running point - is refused
     * with an IllegalStateException rather than returned.
     */
    public static ECPoint multiplySecure(ECPoint p, BigInteger k)
    {
        checkArguments(p, k);
        return checkResult(SM9G1Multiplier.comb(p, k));
    }

    /**
     * Constant-time [a]p + [b]q in G1 for <b>secret</b> scalars a and b and two points each multiplied
     * by many: [r h1]P1 + [r]P_pub-e, which is [r]Q for the recipient's point
     * Q = [h1]P1 + P_pub-e that encryption and encapsulation multiply by their ephemeral r, h1 being
     * the hash of the recipient's identity, and for the peer's point the key exchange multiplies (see
     * {@link org.bouncycastle.crypto.params.SM9EncMasterPublicKeyParameters#multiplyRecipientPoint}).
     * It runs {@link #multiplySecure}'s comb over both points' tables at once, each column doubling
     * the running point once and adding the entry its bits pick out of each table, so that the two
     * multiplications share their doublings and the one inversion that brings the sum to affine
     * coordinates, and keeps each point's table with the point, as {@link #multiplySecure} does:
     * P1's, which the KGC's multiplications of P1 read as well, and the master public key's, made the
     * first time the key is multiplied. Each scalar is blinded with its own random multiple of N, the
     * entries of both tables are carried by the one random factor drawn for the call, and each is
     * read by a full scan of its table from an entry drawn at random, as the comb reads them for one
     * point; the running point at infinity, or equal to the entry it adds, is taken by the same
     * steps as any other, whichever table the entry is read from. The result is checked to lie on
     * the curve, as {@link #multiplySecure}'s is.
     */
    public static ECPoint sumOfTwoMultipliesSecure(ECPoint p, BigInteger a, ECPoint q, BigInteger b)
    {
        checkArguments(p, a);
        checkArguments(q, b);
        return checkResult(SM9G1Multiplier.comb(p, a, q, b));
    }

    // AbstractECMultiplier's check of its result, which the comb, being no AbstractECMultiplier,
    // makes here: an off-curve point is refused with the exception and message it gives
    private static ECPoint checkResult(ECPoint r)
    {
        if (!r.isValid())
        {
            throw new IllegalStateException("Invalid result");
        }
        return r;
    }

    // The endomorphism of G1 that the GLV method splits a scalar over: (x, y) -> (beta x, y) for
    // beta = -(18t^3 + 18t^2 + 9t + 2) mod q, a cube root of 1 in F_q, which on G1, of prime order N,
    // is the multiplication by lambda = -(36t^3 + 18t^2 + 6t + 2) mod N. A scalar k is split into
    // k1 + k2 lambda by rounding over the lattice of the (a, b) with a + b lambda = 0 mod N, whose
    // basis (6t^2 + 2t, -(2t + 1)), (2t + 1, 6t^2 + 4t + 1) has determinant N, with g1 and g2
    // 2^272 (6t^2 + 4t + 1) / N and 2^272 (2t + 1) / N rounded, as ScalarSplitParameters takes
    // them; k1 and k2 come out within 128 bits.
    private static final GLVTypeBEndomorphism G1_ENDOMORPHISM = createEndomorphism();

    // The GLV method over it, for a public scalar times a public point. Stateless as well.
    private static final GLVMultiplier G1_PUBLIC_MULTIPLIER = new GLVMultiplier(G1, G1_ENDOMORPHISM);

    private static GLVTypeBEndomorphism createEndomorphism()
    {
        BigInteger q = G1.getField().getCharacteristic();
        BigInteger t2 = T.multiply(T), t3 = t2.multiply(T);
        BigInteger beta = q.subtract(t3.multiply(BigInteger.valueOf(18)).add(t2.multiply(BigInteger.valueOf(18)))
            .add(T.multiply(BigInteger.valueOf(9))).add(BigInteger.valueOf(2)));
        BigInteger lambda = N.subtract(t3.multiply(BigInteger.valueOf(36)).add(t2.multiply(BigInteger.valueOf(18)))
            .add(T.multiply(BigInteger.valueOf(6))).add(BigInteger.valueOf(2)));
        BigInteger a = T.shiftLeft(1).add(BigInteger.ONE);                          // 2t + 1
        BigInteger b = t2.multiply(BigInteger.valueOf(6)).add(T.shiftLeft(1));      // 6t^2 + 2t
        BigInteger c = b.add(a);                                                    // 6t^2 + 4t + 1
        int bits = N.bitLength() + 16;
        ScalarSplitParameters split = new ScalarSplitParameters(new BigInteger[]{ b, a.negate() },
            new BigInteger[]{ a, c }, rounded(c.shiftLeft(bits), N), rounded(a.shiftLeft(bits), N), bits);
        return new GLVTypeBEndomorphism(G1, new GLVTypeBParameters(beta, lambda, split));
    }

    // x / y rounded to the nearest integer, for positive x and y
    private static BigInteger rounded(BigInteger x, BigInteger y)
    {
        return x.add(y.shiftRight(1)).divide(y);
    }

    /**
     * G1 scalar multiplication by a <b>public</b> scalar of a <b>public</b> point: verification's
     * [h1]S, h1 the hash of the signer's identity and S the point the signature carries. It runs the
     * GLV method over the endomorphism (x, y) -&gt; (beta x, y) of G1, which is the multiplication by a
     * cube root of 1 mod N: the scalar is split into two of half its length, and the point and its
     * image are multiplied by them together, two interleaved windowed NAFs over some 128 bits, where
     * {@link ECPoint#multiply} runs one over all 256. Neither the steps it takes nor the entries it
     * reads are independent of the scalar and the point, and it keeps the multiples of the point it
     * makes, and the point's image, with the point: never for a private key, nor for any value
     * derived from one - {@link #multiplySecure} and {@link #sumOfTwoMultipliesSecure} are for those.
     */
    public static ECPoint multiplyPublic(ECPoint p, BigInteger k)
    {
        checkArguments(p, k);
        return G1_PUBLIC_MULTIPLIER.multiply(p, k);
    }

    private static void checkArguments(ECPoint p, BigInteger k)
    {
        // The comb blinds the scalar with a multiple of N, which gives the same point only for a
        // point whose order divides N - a point of another curve would come back as a wrong multiple
        // of it - and the blinding takes a scalar of at most 256 bits; and the GLV multiplier reduces
        // an over-wide scalar mod N and returns a multiple for it.
        if (p == null || !G1.equals(p.getCurve()) || !p.isValid())
        {
            throw new IllegalArgumentException("base point is not a point of SM9's G1");
        }
        if (k == null || k.signum() < 0 || k.bitLength() > N.bitLength())
        {
            throw new IllegalArgumentException("scalar must be non-negative and at most "
                + N.bitLength() + " bits");
        }
    }

    /**
     * Decode a G1 point from the 65-byte uncompressed form 0x04 || x || y that SM9 writes,
     * or from the one-octet 0x00 that encodes the point at infinity.
     * <p>
     * {@link ECCurve#decodePoint(byte[])} would also take the hybrid form
     * (0x06 / 0x07 || x || y), which carries the same coordinates behind a different prefix
     * byte and so gives every G1 key a second accepted encoding - the malleability already
     * closed for the signature's S component and for ciphertexts. The compressed form is
     * refused as well: GM/T 0044.1 7.1 makes the compressed and hybrid forms optional, and SM9
     * writes neither.
     * <p>
     * Infinity is decoded rather than refused here, so that a caller whose key may not be
     * the point at infinity rejects it in its own terms; no SM9 key may be, and each says
     * so where it is decoded.
     *
     * @param enc the encoded point.
     * @return the decoded point, which is on the curve.
     */
    public static ECPoint g1FromUncompressed(byte[] enc)
    {
        boolean infinity = enc.length == 1 && enc[0] == 0x00;
        if (!infinity && (enc.length != 65 || enc[0] != 0x04 || notBelowQ(enc, 1) || notBelowQ(enc, 33)))
        {
            // a coordinate at or above q among them, as g1FromBytes refuses one
            throw new IllegalArgumentException("invalid SM9 G1 point encoding");
        }
        return G1.decodePoint(enc);
    }

    private SM9Curve()
    {
    }
}
