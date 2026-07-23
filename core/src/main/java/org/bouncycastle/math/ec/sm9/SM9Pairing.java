package org.bouncycastle.math.ec.sm9;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

/**
 * The SM9 R-ate pairing e: G1 x G2 -&gt; G_T over the 256-bit BN curve
 * (GM/T 0044.5-2016). Computed as the optimal-ate/R-ate Miller loop with loop
 * parameter 6t+2, a two-term Frobenius tail, and the final exponentiation
 * f^((q^12-1)/N).
 * <p>
 * This is a correctness-first reference implementation: the Miller loop runs in
 * F_p12 on the twist image, and the Frobenius/final exponentiation are ordinary
 * F_p12 exponentiations. It is deliberately straightforward, not optimised.
 */
public class SM9Pairing
{
    private static final BigInteger Q = Fp2.Q;
    private static final BigInteger Q2 = Q.multiply(Q);
    private static final BigInteger FINAL_EXP = Q.pow(12).subtract(BigInteger.ONE).divide(SM9Curve.N);

    // sextic twist embedding constants: psi(x,y) = (x*w^-2, y*w^-3)
    private static final Fp12 WM2;
    private static final Fp12 WM3;
    static
    {
        Fp12 w2 = Fp12.W.multiply(Fp12.W);
        WM2 = w2.invert();
        WM3 = w2.multiply(Fp12.W).invert();
    }

    private static Fp12 fp2To12(Fp2 x)
    {
        return new Fp12(new Fp4(x, Fp2.ZERO), Fp4.ZERO, Fp4.ZERO);
    }

    private static Fp12 fpTo12(BigInteger a)
    {
        return fp2To12(new Fp2(a, BigInteger.ZERO));
    }

    // EC point over F_p12 (image of the twist under psi)
    private static final class Pt
    {
        final Fp12 x;
        final Fp12 y;

        Pt(Fp12 x, Fp12 y)
        {
            this.x = x;
            this.y = y;
        }

        Pt frobenius(BigInteger e)
        {
            return new Pt(x.pow(e), y.pow(e));
        }

        Pt negate()
        {
            return new Pt(x, y.negate());
        }
    }

    private static Pt psi(SM9G2Point q)
    {
        return new Pt(fp2To12(q.x).multiply(WM2), fp2To12(q.y).multiply(WM3));
    }

    // line-function result: updated running point plus the (denominator-free) line value at P
    private static final class Step
    {
        final Pt t;
        final Fp12 val;

        Step(Pt t, Fp12 val)
        {
            this.t = t;
            this.val = val;
        }
    }

    private static Step lineDouble(Pt t, Fp12 xP, Fp12 yP)
    {
        Fp12 x = t.x, y = t.y;
        Fp12 x2 = x.square();
        Fp12 lam = x2.add(x2).add(x2).multiply(y.add(y).invert());  // 3x^2 / 2y
        Fp12 x3 = lam.square().subtract(x).subtract(x);
        Fp12 y3 = lam.multiply(x.subtract(x3)).subtract(y);
        Fp12 val = yP.subtract(y).subtract(lam.multiply(xP.subtract(x)));
        return new Step(new Pt(x3, y3), val);
    }

    private static Step lineAdd(Pt t, Pt q, Fp12 xP, Fp12 yP)
    {
        Fp12 x1 = t.x, y1 = t.y, x2 = q.x, y2 = q.y;
        Fp12 lam = y2.subtract(y1).multiply(x2.subtract(x1).invert());
        Fp12 x3 = lam.square().subtract(x1).subtract(x2);
        Fp12 y3 = lam.multiply(x1.subtract(x3)).subtract(y1);
        Fp12 val = yP.subtract(y1).subtract(lam.multiply(xP.subtract(x1)));
        return new Step(new Pt(x3, y3), val);
    }

    /**
     * e(P, Q) for P in G1 (a point of E(F_q)) and Q in G2 (a point of the twist).
     */
    public static Fp12 pairing(ECPoint p, SM9G2Point q)
    {
        ECPoint pn = p.normalize();
        Fp12 xP = fpTo12(pn.getAffineXCoord().toBigInteger());
        Fp12 yP = fpTo12(pn.getAffineYCoord().toBigInteger());

        Pt qp = psi(q);
        Fp12 f = Fp12.ONE;
        Pt t = qp;

        BigInteger loop = SM9Curve.LOOP;
        for (int i = loop.bitLength() - 2; i >= 0; --i)
        {
            f = f.square();
            Step d = lineDouble(t, xP, yP);
            t = d.t;
            f = f.multiply(d.val);
            if (loop.testBit(i))
            {
                Step a = lineAdd(t, qp, xP, yP);
                t = a.t;
                f = f.multiply(a.val);
            }
        }

        // R-ate / optimal-ate Frobenius tail: Q1 = pi(Q), Q2 = pi^2(Q)
        Pt q1 = qp.frobenius(Q);
        Pt q2 = qp.frobenius(Q2);
        Step s1 = lineAdd(t, q1, xP, yP);
        t = s1.t;
        f = f.multiply(s1.val);
        Step s2 = lineAdd(t, q2.negate(), xP, yP);
        f = f.multiply(s2.val);

        return f.pow(FINAL_EXP);
    }

    /**
     * Serialize a G_T element to bytes per GM/T 0044.5: high dimension first,
     * recursively over the 1-2-4-12 tower (w^2, w^1, w^0; then v^1, v^0; then
     * u^1, u^0), 32 bytes per F_q component; 384 bytes total.
     */
    public static byte[] toBytes(Fp12 z)
    {
        byte[] out = new byte[12 * 32];
        int off = 0;
        off = putBlock(out, off, z.c);
        off = putBlock(out, off, z.b);
        putBlock(out, off, z.a);
        return out;
    }

    private static int putBlock(byte[] out, int off, Fp4 e)
    {
        off = putFp(out, off, e.b.b);
        off = putFp(out, off, e.b.a);
        off = putFp(out, off, e.a.b);
        off = putFp(out, off, e.a.a);
        return off;
    }

    private static int putFp(byte[] out, int off, BigInteger v)
    {
        byte[] b = BigIntegers.asUnsignedByteArray(32, v.mod(Q));
        System.arraycopy(b, 0, out, off, 32);
        return off + 32;
    }

    private SM9Pairing()
    {
    }
}
