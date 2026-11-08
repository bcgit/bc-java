package org.bouncycastle.crypto.bls;

import java.math.BigInteger;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.hash2curve.H2cUtils;
import org.bouncycastle.crypto.hash2curve.MessageExpansion;
import org.bouncycastle.crypto.hash2curve.impl.XmdMessageExpansion;
import org.bouncycastle.util.Arrays;

/**
 * Implementation of the BLS12381G2_XMD:SHA-256_SSWU_RO_ hash-to-curve suite
 * (RFC 9380 sec. 8.8.2): a deterministic, uniform map from a byte string and
 * a domain-separation tag to a point in the BLS12-381 G2 prime-order
 * subgroup.
 * <p>
 * Pipeline:
 * <ol>
 *   <li>{@code expand_message_xmd(msg, dst, 256)} produces 256 bytes (count=2,
 *       m=2, L=64).</li>
 *   <li>The bytes are split into two Fp^2 elements u[0], u[1].</li>
 *   <li>Each is run through SSWU on the 3-isogenous helper curve E' (with
 *       A' = 240*I, B' = 1012*(1+I), Z = -(2+I)).</li>
 *   <li>The results are mapped to E by the iso_3 rational map (RFC 9380
 *       App. E.3).</li>
 *   <li>The two G2 points are added, and the cofactor is cleared by
 *       scalar-multiplication by h_eff.</li>
 * </ol>
 */
public class BLS12_381G2HashToCurve
{
    private static final int L = 64;
    private static final int K = 128;

    /** A' coefficient of the SSWU helper curve E': 240 * I. */
    private static final Fp2Element A_PRIME = Fp2Element.of(0, 240);

    /** B' coefficient of E': 1012 * (1 + I). */
    private static final Fp2Element B_PRIME = Fp2Element.of(1012, 1012);

    /** SSWU Z parameter: -(2 + I). */
    private static final Fp2Element Z = Fp2Element.of(-2, -1);

    /** (p + 1) / 4: in Fp, a^((p+1)/4) is a square root of a whenever a is a square (p = 3 mod 4). */
    private static final BigInteger SQRT_EXP = Fp2Element.P.add(BigInteger.ONE).shiftRight(2);

    /** 1/2 in Fp. */
    private static final BigInteger HALF = BigInteger.valueOf(2).modInverse(Fp2Element.P);

    /**
     * A square root of -N(Z) = -5 in Fp. Z is not a square in Fp^2, so its norm 5
     * is not a square in Fp; neither is -1 (p = 3 mod 4), so -5 is.
     */
    private static final BigInteger SQRT_MINUS_NORM_Z;

    static
    {
        BigInteger p = Fp2Element.P;
        BigInteger minusNormZ = p.subtract(Z.c0().multiply(Z.c0()).add(Z.c1().multiply(Z.c1())).mod(p));
        SQRT_MINUS_NORM_Z = minusNormZ.modPow(SQRT_EXP, p);
        if (!SQRT_MINUS_NORM_Z.multiply(SQRT_MINUS_NORM_Z).mod(p).equals(minusNormZ))
        {
            throw new IllegalStateException("-N(Z) must be a square in Fp");
        }
    }

    /** The BLS12-381 parameter x = -0xd201000000010000 (RFC 9380 App. G.3 c1). */
    private static final BigInteger X = new BigInteger("-d201000000010000", 16);

    /** iso_3 x_num coefficients k_(1,0..3). */
    private static final Fp2Element[] K1 = {
        Fp2Element.of(
            new BigInteger("5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6", 16),
            new BigInteger("5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6", 16)),
        Fp2Element.of(
            BigInteger.ZERO,
            new BigInteger("11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71a", 16)),
        Fp2Element.of(
            new BigInteger("11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71e", 16),
            new BigInteger("8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38d", 16)),
        Fp2Element.of(
            new BigInteger("171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1", 16),
            BigInteger.ZERO),
    };

    /** iso_3 x_den coefficients k_(2,0..1) (leading 1 is implicit per RFC 9380). */
    private static final Fp2Element[] K2 = {
        Fp2Element.of(
            BigInteger.ZERO,
            new BigInteger("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63", 16)),
        Fp2Element.of(
            BigInteger.valueOf(0xc),
            new BigInteger("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9f", 16)),
    };

    /** iso_3 y_num coefficients k_(3,0..3). */
    private static final Fp2Element[] K3 = {
        Fp2Element.of(
            new BigInteger("1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706", 16),
            new BigInteger("1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706", 16)),
        Fp2Element.of(
            BigInteger.ZERO,
            new BigInteger("5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97be", 16)),
        Fp2Element.of(
            new BigInteger("11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71c", 16),
            new BigInteger("8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38f", 16)),
        Fp2Element.of(
            new BigInteger("124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286b0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10", 16),
            BigInteger.ZERO),
    };

    /** iso_3 y_den coefficients k_(4,0..2) (leading 1 is implicit per RFC 9380). */
    private static final Fp2Element[] K4 = {
        Fp2Element.of(
            new BigInteger("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb", 16),
            new BigInteger("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb", 16)),
        Fp2Element.of(
            BigInteger.ZERO,
            new BigInteger("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3", 16)),
        Fp2Element.of(
            BigInteger.valueOf(0x12),
            new BigInteger("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99", 16)),
    };

    private final byte[] dst;
    private final MessageExpansion messageExpansion;

    public BLS12_381G2HashToCurve(byte[] dst)
    {
        this.dst = Arrays.clone(dst);
        this.messageExpansion = new XmdMessageExpansion(SHA256Digest.newInstance(), K);
    }

    public BLS12_381G2Point hashToCurve(byte[] message)
    {
        Fp2Element[] u = hashToField(message);
        BLS12_381G2Point q0 = mapToCurveAndIso3(u[0]);
        BLS12_381G2Point q1 = mapToCurveAndIso3(u[1]);
        BLS12_381G2Point r = q0.add(q1);
        return clearCofactor(r);
    }

    /**
     * {@code h_eff * P} by the endomorphism method of Budroni and Pintore
     * (RFC 9380 App. G.3, {@code clear_cofactor_bls12381_g2}):
     * {@code [x^2 - x - 1]P + [x - 1]psi(P) + psi^2(2P)}, using two scalar
     * multiplications by the 64-bit x instead of one by the 636-bit
     * {@code h_eff}. Package-private so the test tree can check it against
     * {@code P.multiply(BLS12_381G2.H_EFF)}.
     */
    static BLS12_381G2Point clearCofactor(BLS12_381G2Point p)
    {
        BLS12_381G2Point t1 = p.multiply(X);
        BLS12_381G2Point t2 = BLS12_381SubgroupCheck.psiG2(p);
        BLS12_381G2Point t3 = BLS12_381SubgroupCheck.psiG2(BLS12_381SubgroupCheck.psiG2(p.doublePoint()));
        t3 = t3.add(t2.negate());
        t2 = t1.add(t2).multiply(X);
        t3 = t3.add(t2).add(t1.negate());
        return t3.add(p.negate());
    }

    /**
     * Stage 1: expands {@code message} into two Fp&sup2; field elements per
     * RFC 9380 sec. 5.3. Exposed for layered testing and for callers that
     * want the raw field elements without the curve mapping.
     */
    public Fp2Element[] hashToField(byte[] message)
    {
        byte[] uniformBytes = messageExpansion.expandMessage(message, dst, 2 * 2 * L);
        Fp2Element[] u = new Fp2Element[2];
        for (int i = 0; i < 2; ++i)
        {
            BigInteger c0 = H2cUtils.os2ip(Arrays.copyOfRange(uniformBytes, (2 * i) * L, (2 * i + 1) * L)).mod(Fp2Element.P);
            BigInteger c1 = H2cUtils.os2ip(Arrays.copyOfRange(uniformBytes, (2 * i + 1) * L, (2 * i + 2) * L)).mod(Fp2Element.P);
            u[i] = Fp2Element.of(c0, c1);
        }
        return u;
    }

    /**
     * Stages 2-3: simplified SWU on E' followed by iso_3 to E. Package-private
     * so the test tree can check the RFC 9380 Q0 / Q1 intermediate values;
     * returns a point on E that has not yet had its cofactor cleared, so it is
     * generally not in the prime-order subgroup.
     */
    BLS12_381G2Point mapToCurveAndIso3(Fp2Element u)
    {
        // Simplified SWU on E' (RFC 9380 sec. F.2 / 6.6.3).
        Fp2Element tv1 = Z.mul(u.square());
        Fp2Element tv2 = tv1.square().add(tv1);
        Fp2Element tv3 = B_PRIME.mul(tv2.add(Fp2Element.ONE));
        Fp2Element tv4 = A_PRIME.mul(tv2.isZero() ? Z : tv2.neg());
        Fp2Element gx1Num = tv3.square().add(A_PRIME.mul(tv4.square())).mul(tv3)
            .add(B_PRIME.mul(tv4.square().mul(tv4)));
        Fp2Element gx1Den = tv4.square().mul(tv4);

        // gx1 = gx1Num / gx1Den = gx1Num * gx1Den / gx1Den^2, so sqrt(gx1) =
        // sqrt(gx1Num * gx1Den) / gx1Den, and gx1Den = tv4^3: one inversion, of
        // tv4, serves x' and y' (RFC 9380 App. F.2, sqrt_ratio).
        Fp2Element tv4Inv = tv4.inverse();
        Fp2Element denInv = tv4Inv.square().mul(tv4Inv);
        Fp2Element[] root = new Fp2Element[1];
        boolean isSquare = sqrtOrSqrtZ(gx1Num.mul(gx1Den), root);

        Fp2Element xPrime;
        Fp2Element yPrime;
        if (isSquare)
        {
            xPrime = tv3.mul(tv4Inv);
            yPrime = root[0].mul(denInv);
        }
        else
        {
            xPrime = tv1.mul(tv3).mul(tv4Inv);
            yPrime = tv1.mul(u).mul(root[0]).mul(denInv);
        }
        // Any square root will do: the sign is fixed here, as RFC 9380 requires.
        if (u.sgn0() != yPrime.sgn0())
        {
            yPrime = yPrime.neg();
        }

        // iso_3 evaluation (RFC 9380 App. E.3), with one inversion for both denominators.
        Fp2Element xNum = horner(K1, xPrime);
        Fp2Element xDen = horner(K2, xPrime).add(xPrime.square());
        Fp2Element yNum = horner(K3, xPrime);
        Fp2Element yDen = horner(K4, xPrime).add(xPrime.square().mul(xPrime));

        Fp2Element denProdInv = xDen.mul(yDen).inverse();
        Fp2Element x = xNum.mul(denProdInv).mul(yDen);
        Fp2Element y = yPrime.mul(yNum).mul(denProdInv).mul(xDen);

        return BLS12_381G2Point.ofUnchecked(x, y);
    }

    /**
     * Sets {@code root[0]} to a square root of {@code w} and returns true when
     * {@code w} is a square in Fp^2; otherwise sets it to a square root of
     * {@code Z * w} (a square, as Z is not) and returns false. This is
     * RFC 9380's {@code sqrt_ratio(w, 1)} up to the choice of root.
     * <p>
     * Works in Fp, as p = 3 (mod 4) allows: {@code a + b*I} is a square exactly
     * when its norm {@code a^2 + b^2} is a square in Fp, and then, with
     * {@code g = sqrt(a^2 + b^2)}, one of {@code (a + g)/2} and {@code (a - g)/2}
     * is a square {@code x0^2} and {@code x0 + (b / 2x0)*I} is a root. That costs
     * two or three exponentiations in Fp, against the two or three over Fp^2
     * (one with a 762-bit exponent) of {@link Fp2Element#isSquare} and
     * {@link Fp2Element#sqrtOrNull}. Variable time, like the rest of this class;
     * the input is derived from the public message. Package-private for the
     * test tree.
     */
    static boolean sqrtOrSqrtZ(Fp2Element w, Fp2Element[] root)
    {
        BigInteger p = Fp2Element.P;
        BigInteger a = w.c0(), b = w.c1();
        BigInteger norm = a.multiply(a).add(b.multiply(b)).mod(p);
        BigInteger g = norm.modPow(SQRT_EXP, p);
        boolean isSquare = g.multiply(g).mod(p).equals(norm);
        if (!isSquare)
        {
            // g^2 = -norm, and N(Z * w) = 5 * norm = (-5) * (-norm), so its root is sqrt(-5) * g.
            Fp2Element zw = Z.mul(w);
            a = zw.c0();
            b = zw.c1();
            g = SQRT_MINUS_NORM_Z.multiply(g).mod(p);
        }
        root[0] = sqrtOfSquare(a, b, g);
        return isSquare;
    }

    /** A square root of the square {@code a + b*I}, given a square root {@code g} of its norm. */
    private static Fp2Element sqrtOfSquare(BigInteger a, BigInteger b, BigInteger g)
    {
        BigInteger p = Fp2Element.P;
        if (b.signum() == 0)
        {
            // a in Fp. s = a^((p+1)/4) has s^2 = a * a^((p-1)/2) = a or -a; in the
            // second case a is not a square in Fp and (s*I)^2 = -s^2 = a.
            BigInteger s = a.modPow(SQRT_EXP, p);
            if (s.multiply(s).mod(p).equals(a))
            {
                return Fp2Element.of(s, BigInteger.ZERO);
            }
            return Fp2Element.of(BigInteger.ZERO, s);
        }
        // b != 0: (a + g)/2 * (a - g)/2 = -b^2/4 is a non-square, so exactly one factor is a square.
        BigInteger delta = a.add(g).multiply(HALF).mod(p);
        BigInteger x0 = delta.modPow(SQRT_EXP, p);
        if (!x0.multiply(x0).mod(p).equals(delta))
        {
            delta = a.subtract(g).multiply(HALF).mod(p);
            x0 = delta.modPow(SQRT_EXP, p);
        }
        BigInteger x1 = b.multiply(x0.shiftLeft(1).modInverse(p)).mod(p);
        return Fp2Element.of(x0, x1);
    }

    /**
     * Horner evaluation of {@code coeffs[n-1]*x^(n-1) + ... + coeffs[1]*x + coeffs[0]}.
     */
    private static Fp2Element horner(Fp2Element[] coeffs, Fp2Element x)
    {
        Fp2Element acc = coeffs[coeffs.length - 1];
        for (int i = coeffs.length - 2; i >= 0; --i)
        {
            acc = acc.mul(x).add(coeffs[i]);
        }
        return acc;
    }
}
