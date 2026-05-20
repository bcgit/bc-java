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
        return r.multiply(BLS12_381G2.H_EFF);
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
     * Stages 2-3: simplified SWU on E' followed by iso_3 to E. Exposed for
     * layered testing; returns a point on E that has not yet had its
     * cofactor cleared, so it is generally not in the prime-order subgroup.
     */
    public BLS12_381G2Point mapToCurveAndIso3(Fp2Element u)
    {
        // Simplified SWU on E' (RFC 9380 sec. F.2 / 6.6.3).
        Fp2Element tv1 = Z.mul(u.square());
        Fp2Element tv2 = tv1.square().add(tv1);
        Fp2Element tv3 = B_PRIME.mul(tv2.add(Fp2Element.ONE));
        Fp2Element tv4 = A_PRIME.mul(tv2.isZero() ? Z : tv2.neg());
        Fp2Element gx1Num = tv3.square().add(A_PRIME.mul(tv4.square())).mul(tv3)
            .add(B_PRIME.mul(tv4.square().mul(tv4)));
        Fp2Element gx1Den = tv4.square().mul(tv4);

        Fp2Element xPrime;
        Fp2Element yPrime;
        Fp2Element ratio = gx1Num.mul(gx1Den.inverse());
        if (ratio.isSquare())
        {
            xPrime = tv3.mul(tv4.inverse());
            yPrime = ratio.sqrtOrNull();
        }
        else
        {
            xPrime = tv1.mul(tv3).mul(tv4.inverse());
            Fp2Element zRatio = Z.mul(ratio);
            Fp2Element zRatioSqrt = zRatio.sqrtOrNull();
            yPrime = tv1.mul(u).mul(zRatioSqrt);
        }
        if (u.sgn0() != yPrime.sgn0())
        {
            yPrime = yPrime.neg();
        }

        // iso_3 evaluation (RFC 9380 App. E.3).
        Fp2Element xNum = horner(K1, xPrime);
        Fp2Element xDen = horner(K2, xPrime).add(xPrime.square());
        Fp2Element yNum = horner(K3, xPrime);
        Fp2Element yDen = horner(K4, xPrime).add(xPrime.square().mul(xPrime));

        Fp2Element x = xNum.mul(xDen.inverse());
        Fp2Element y = yPrime.mul(yNum).mul(yDen.inverse());

        return BLS12_381G2Point.ofUnchecked(x, y);
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
