package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Couple-point arithmetic on elliptic-curve products E1 × E2.
 * Java port of {@code src/hd/ref/lvlx/hd.c}.
 *
 * <p>The number-of-extra-torsion constant {@code HD_extra_torsion = 2} comes
 * from {@code hd.h}.</p>
 */
final class HdOps
{
    /**
     * {@code HD_extra_torsion} from the C reference.
     */
    public static final int HD_EXTRA_TORSION = 2;

    private HdOps()
    {
    }

    /**
     * {@code double_couple_point}: out ← (2·P1, 2·P2).
     */
    public static void doubleCouplePoint(ThetaCouplePoint out, ThetaCouplePoint in, ThetaCoupleCurve E1E2)
    {
        EcLadder.dbl(out.P1, in.P1, E1E2.E1);
        EcLadder.dbl(out.P2, in.P2, E1E2.E2);
    }

    /**
     * {@code double_couple_point_iter}: out ← [2^n] (P1, P2).
     */
    public static void doubleCouplePointIter(ThetaCouplePoint out, int n,
                                             ThetaCouplePoint in, ThetaCoupleCurve E1E2)
    {
        if (n == 0)
        {
            ThetaCouplePoint.copy(out, in);
            return;
        }
        doubleCouplePoint(out, in, E1E2);
        for (int i = 0; i < n - 1; i++)
        {
            doubleCouplePoint(out, out, E1E2);
        }
    }

    /**
     * {@code double_couple_jac_point}: componentwise Jacobian doubling.
     */
    public static void doubleCoupleJacPoint(ThetaCoupleJacPoint out, ThetaCoupleJacPoint in,
                                            ThetaCoupleCurve E1E2)
    {
        EcJac.dbl(out.P1, in.P1, E1E2.E1);
        EcJac.dbl(out.P2, in.P2, E1E2.E2);
    }

    /**
     * {@code double_couple_jac_point_iter}: iterated Jacobian doubling using
     * the Weierstrass-modified-Jacobian shortcut for n > 1.
     */
    public static void doubleCoupleJacPointIter(ThetaCoupleJacPoint out, int n,
                                                ThetaCoupleJacPoint in, ThetaCoupleCurve E1E2)
    {
        if (n == 0)
        {
            ThetaCoupleJacPoint.copy(out, in);
            return;
        }
        if (n == 1)
        {
            doubleCoupleJacPoint(out, in, E1E2);
            return;
        }
        // Use each curve's field — the per-iteration dblW call has no curve
        // parameter and would otherwise fall through to the lvl1 default.
        org.bouncycastle.pqc.crypto.sqisign.GfField f1 = E1E2.E1.field;
        org.bouncycastle.pqc.crypto.sqisign.GfField f2 = E1E2.E2.field;
        Fp2 a1 = Fp2.zero(), a2 = Fp2.zero();
        Fp2 t1 = Fp2.zero(), t2 = Fp2.zero();
        EcJac.toWs(out.P1, t1, a1, in.P1, E1E2.E1);
        EcJac.toWs(out.P2, t2, a2, in.P2, E1E2.E2);

        EcJac.dblW(f1, out.P1, t1, out.P1, t1);
        EcJac.dblW(f2, out.P2, t2, out.P2, t2);
        for (int i = 0; i < n - 1; i++)
        {
            EcJac.dblW(f1, out.P1, t1, out.P1, t1);
            EcJac.dblW(f2, out.P2, t2, out.P2, t2);
        }

        EcJac.fromWs(out.P1, out.P1, a1, E1E2.E1);
        EcJac.fromWs(out.P2, out.P2, a2, E1E2.E2);
    }

    /**
     * {@code couple_jac_to_xz}: forget the y-coordinates.
     */
    public static void coupleJacToXz(org.bouncycastle.pqc.crypto.sqisign.GfField field,
                                     ThetaCouplePoint P, ThetaCoupleJacPoint xyP)
    {
        EcJac.toXz(field, P.P1, xyP.P1);
        EcJac.toXz(field, P.P2, xyP.P2);
    }

    /**
     * {@code copy_bases_to_kernel}: assemble a (2,2)-isogeny kernel
     * (T1, T2, T1-T2) from x-only bases on E1 and E2.
     */
    public static void copyBasesToKernel(ThetaKernelCouplePoints ker, EcBasis B1, EcBasis B2)
    {
        EcPoint.copy(ker.T1.P1, B1.P);
        EcPoint.copy(ker.T2.P1, B1.Q);
        EcPoint.copy(ker.T1m2.P1, B1.PmQ);

        EcPoint.copy(ker.T1.P2, B2.P);
        EcPoint.copy(ker.T2.P2, B2.Q);
        EcPoint.copy(ker.T1m2.P2, B2.PmQ);
    }
}
