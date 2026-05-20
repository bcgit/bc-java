package org.bouncycastle.crypto.hash2curve.impl;

import java.math.BigInteger;

import org.bouncycastle.crypto.hash2curve.CurveProcessor;
import org.bouncycastle.crypto.hash2curve.data.AffineXY;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Curve processor for Montgomery curves of the form B * y^2 = x^3 + A * x^2 + x
 * 
 * Internally we treat this as a long Weierstrass curve y^2 = x^3 + a2 * x^2 + a4 * x + a6 with a2 =
 * A / B, a4 = 1 / B, a6 = 0. All arithmetic is done explicitly in F_p using these formulas, not via
 * the ECPoint group operations, because BouncyCastle's Montgomery implementation does not use this
 * model directly.
 */
public class MontgomeryCurveProcessor implements CurveProcessor
{
    /** The elliptic curve for the instance */
    private final ECCurve curve;
    /** The curve field characteristic */
    private final BigInteger p;

    // Weierstrass-style coefficients derived from Montgomery (A, B)
//    private final BigInteger a2; // = A / B mod p
//    private final BigInteger a4; // = 1 / B mod p
//    private final BigInteger a6; // = 0

    // Effective cofactor h_eff (e.g. 8 for curve25519_XMD:SHA-512_ELL2_RO_)
    private final BigInteger hEff;
    private final int J;
    private final int K;

    /**
     * Constructs a MontgomeryCurveProcessor object for processing elliptic curves represented in the
     * Montgomery model. Computes and initializes curve parameters for use in point operations and
     * transformations.
     *
     * @param curve the elliptic curve to be processed, represented using the ECCurve class
     * @param J parameter J of the Montgomery curve equation, used for internal calculations
     * @param K parameter K of the Montgomery curve equation, used for internal calculations
     * @param hEff the effective cofactor value for the curve, utilized in certain operations
     */
    public MontgomeryCurveProcessor(ECCurve curve, int J, int K, int hEff)
    {
        this.J = J;
        this.K = K;
        this.curve = curve;
        this.p = curve.getField().getCharacteristic();
//        BigInteger Binv = BigInteger.valueOf(K).modInverse(p);
//        this.a2 = BigInteger.valueOf(J).multiply(Binv).mod(p); // A/B
//        this.a4 = Binv;
//        this.a6 = BigInteger.ZERO;
        this.hEff = BigInteger.valueOf(hEff);
    }

    /**
     * Adds two elliptic curve points on the Montgomery curve model and returns the resulting point. The
     * method internally converts Montgomery coordinates to Weierstrass coordinates to perform the group
     * law, then converts the result back to Montgomery coordinates.
     *
     * @param P the first elliptic curve point on the Montgomery curve model
     * @param Q the second elliptic curve point on the Montgomery curve model
     * @return the resulting elliptic curve point on the Montgomery curve model after addition
     */
    public ECPoint add(final ECPoint P, final ECPoint Q)
    {
        // Convert Montgomery-coded inputs to real Weierstrass ECPoints
        final ECPoint Pw = Fmtow(P).toPoint(curve);
        final ECPoint Qw = Fmtow(Q).toPoint(curve);

        // Do group law using BC's Weierstrass implementation
        final ECPoint Rw = Pw.add(Qw).normalize();

        // Convert back to Montgomery coordinates, then pack into an ECPoint carrier
        return Fwtom(Rw).toPoint(curve);
    }

    /**
     * Clears the cofactor of the given elliptic curve point using the efficient cofactor value. If the
     * input point is at infinity, the same point is returned. Otherwise, it transforms the point into
     * the short-Weierstrass model, multiplies by the effective cofactor, and normalizes the resulting
     * point.
     *
     * @param P the elliptic curve point on the Montgomery curve model
     * @return the resulting elliptic curve point in the short-Weierstrass model with the cofactor
     * cleared
     */
    public ECPoint clearCofactor(final ECPoint P)
    {
        if (P.isInfinity())
        {
            return P;
        }
        final ECPoint Pw = Fmtow(P).toPoint(curve);
        return Pw.multiply(hEff).normalize();
    }

    public AffineXY mapToAffineXY(final ECPoint p)
    {
        return Fwtom(p.normalize());
    }

    /**
     * Convert Montgomery-model coordinates (xM, yM) to the corresponding short-Weierstrass coordinates
     * (xW, yW) using the standard change of variables:
     *
     * xW = xM + A/3 yW = yM / K
     *
     * where A = J/K (mod p) and B = 1/K^2 (so sqrt(B) = 1/K exists).
     *
     * IMPORTANT: This returns coordinates only. It does NOT create a BC ECPoint.
     */
    private AffineXY Fmtow(final BigInteger xM, final BigInteger yM)
    {
        final BigInteger inv3 = BigInteger.valueOf(3).modInverse(p);

        // A = J/K
        final BigInteger A = BigInteger.valueOf(J).mod(p).multiply(BigInteger.valueOf(K).mod(p).modInverse(p)).mod(p);

        // xW = xM + A/3
        final BigInteger xW = xM.mod(p).add(A.multiply(inv3).mod(p)).mod(p);

        // yW = yM / K
        final BigInteger invK = BigInteger.valueOf(K).mod(p).modInverse(p);
        final BigInteger yW = yM.mod(p).multiply(invK).mod(p);

        return new AffineXY(xW, yW);
    }

    /**
     * Convert short-Weierstrass coordinates (xW, yW) to Montgomery-model coordinates (xM, yM):
     *
     * xM = xW - A/3 yM = yW * K
     *
     * IMPORTANT: This returns coordinates only. It does NOT create a BC ECPoint.
     */
    private AffineXY Fwtom(final BigInteger xW, final BigInteger yW)
    {
        final BigInteger inv3 = BigInteger.valueOf(3).modInverse(p);

        // A = J/K
        final BigInteger A = BigInteger.valueOf(J).mod(p).multiply(BigInteger.valueOf(K).mod(p).modInverse(p)).mod(p);

        // xM = xW - A/3
        final BigInteger xM = xW.mod(p).subtract(A.multiply(inv3).mod(p)).mod(p);

        // yM = yW * K
        final BigInteger yM = yW.mod(p).multiply(BigInteger.valueOf(K).mod(p)).mod(p);

        return new AffineXY(xM, yM);
    }

    /**
     * Converts the given elliptic curve point from its Montgomery-model representation to the
     * corresponding short-Weierstrass affine coordinates. If the input point is at infinity, it returns
     * coordinates (0, 0). Otherwise, the point is normalized before extracting and transforming its
     * affine coordinates.
     *
     * @param Pm the elliptic curve point on the Montgomery model to be converted
     * @return the affine coordinates in the short-Weierstrass representation
     */
    private AffineXY Fmtow(final ECPoint Pm)
    {
        if (Pm.isInfinity())
        {
            return new AffineXY(BigInteger.ZERO, BigInteger.ZERO);
        }
        final ECPoint Pn = Pm.normalize();
        return Fmtow(Pn.getAffineXCoord().toBigInteger(), Pn.getAffineYCoord().toBigInteger());
    }

    /**
     * Converts the given elliptic curve point from its short-Weierstrass affine coordinates to the
     * corresponding Montgomery-model representation. If the point is at infinity, it returns
     * coordinates (0, 0). Otherwise, the point is normalized before extracting and transforming its
     * affine coordinates.
     *
     * @param Pw the elliptic curve point in the short-Weierstrass representation to be converted
     * @return the affine coordinates in the Montgomery-model representation
     */
    private AffineXY Fwtom(final ECPoint Pw)
    {
        if (Pw.isInfinity())
        {
            return new AffineXY(BigInteger.ZERO, BigInteger.ZERO);
        }
        final ECPoint Pn = Pw.normalize();
        return Fwtom(Pn.getAffineXCoord().toBigInteger(), Pn.getAffineYCoord().toBigInteger());
    }
}
