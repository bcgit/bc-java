package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Biextension-based Weil pairing on the 2^e-torsion subgroup, using cubical
 * torsor arithmetic. Java port of the level-independent core of
 * {@code src/ec/ref/lvlx/biextension.c}.
 *
 * <p>The reduced Tate pairing ({@code reduced_tate}, {@code clear_cofac}) and
 * the discrete-log routines depend on the level-specific precomp constant
 * {@code p_cofactor_for_2f}; they will land in a separate lvl1-specific class
 * once the precomp tables are regenerated for Java.</p>
 */
final class EcBiext
{
    private EcBiext()
    {
    }

    /**
     * {@code cubicalADD}: cubical addition R ← P + Q given the inverse of
     * x(P - Q) as {@code ixPQ}. Like xADD but with PQ = (1 : z) "antinormalised".
     */
    public static void cubicalADD(GfField field, EcPoint R, EcPoint P, EcPoint Q, Fp2 ixPQ)
    {
        Fp2 t0 = Fp2.zero(), t1 = Fp2.zero();
        Fp2 t2 = Fp2.zero(), t3 = Fp2.zero();

        field.fp2Add(t0, P.x, P.z);
        field.fp2Sub(t1, P.x, P.z);
        field.fp2Add(t2, Q.x, Q.z);
        field.fp2Sub(t3, Q.x, Q.z);
        field.fp2Mul(t0, t0, t3);
        field.fp2Mul(t1, t1, t2);
        field.fp2Add(t2, t0, t1);
        field.fp2Sub(t3, t0, t1);
        field.fp2Sqr(R.z, t3);
        field.fp2Sqr(t2, t2);
        field.fp2Mul(R.x, ixPQ, t2);
    }

    /**
     * {@code cubicalDBLADD}: simultaneously compute P + Q and 2Q given cubical
     * reps of P and Q plus x(P - Q) = (1 : ixPQ). A24 must be normalised
     * ((A+2)/4 : 1).
     */
    public static void cubicalDBLADD(GfField field, EcPoint PpQ, EcPoint QQ, EcPoint P, EcPoint Q,
                                     Fp2 ixPQ, EcPoint A24)
    {
        Fp2 t0 = Fp2.zero(), t1 = Fp2.zero();
        Fp2 t2 = Fp2.zero(), t3 = Fp2.zero();

        field.fp2Add(t0, P.x, P.z);
        field.fp2Sub(t1, P.x, P.z);
        field.fp2Add(PpQ.x, Q.x, Q.z);
        field.fp2Sub(t3, Q.x, Q.z);
        field.fp2Sqr(t2, PpQ.x);
        field.fp2Sqr(QQ.z, t3);
        field.fp2Mul(t0, t0, t3);
        field.fp2Mul(t1, t1, PpQ.x);
        field.fp2Add(PpQ.x, t0, t1);
        field.fp2Sub(t3, t0, t1);
        field.fp2Sqr(PpQ.z, t3);
        field.fp2Sqr(PpQ.x, PpQ.x);
        field.fp2Mul(PpQ.x, ixPQ, PpQ.x);
        field.fp2Sub(t3, t2, QQ.z);
        field.fp2Mul(QQ.x, t2, QQ.z);
        field.fp2Mul(t0, t3, A24.x);
        field.fp2Add(t0, t0, QQ.z);
        field.fp2Mul(QQ.z, t0, t3);
    }

    /** Iterative biextension doubling: {@code PnQ ← P + [2^e] Q}, {@code nQ ← [2^e] Q}. */
    public static void biextLadder2e(GfField field, int e, EcPoint PnQ, EcPoint nQ,
                                     EcPoint PQ, EcPoint Q, Fp2 ixP, EcPoint A24)
    {
        EcPoint.copy(PnQ, PQ);
        EcPoint.copy(nQ, Q);
        for (int i = 0; i < e; i++)
        {
            cubicalDBLADD(field, PnQ, nQ, PnQ, nQ, ixP, A24);
        }
    }

    /** {@code point_ratio}: write the monodromy ratio as a (X : Z) point. */
    public static void pointRatio(GfField field, EcPoint R, EcPoint PnQ, EcPoint nQ, EcPoint P)
    {
        field.fp2Mul(R.x, nQ.x, P.x);
        Fp2.copy(R.z, PnQ.x);
    }

    /**
     * {@code translate}: cubical translation of P by the 2-torsion point T.
     * Branches handle T = (A : 0), (0 : B), (A : B) cases.
     */
    public static void translate(GfField field, EcPoint P, EcPoint T)
    {
        Fp2 t0 = Fp2.zero(), t1 = Fp2.zero();
        Fp2 PXnew = Fp2.zero(), PZnew = Fp2.zero();

        field.fp2Mul(t0, T.x, P.x);
        field.fp2Mul(t1, T.z, P.z);
        field.fp2Sub(PXnew, t0, t1);

        field.fp2Mul(t0, T.z, P.x);
        field.fp2Mul(t1, T.x, P.z);
        field.fp2Sub(PZnew, t0, t1);

        int TAisZero = Fp2.isZero(T.x);
        Fp2.select(PXnew, PXnew, P.z, TAisZero);
        Fp2.select(PZnew, PZnew, P.x, TAisZero);

        int TBisZero = Fp2.isZero(T.z);
        Fp2.select(PXnew, PXnew, P.x, TBisZero);
        Fp2.select(PZnew, PZnew, P.z, TBisZero);

        Fp2.copy(P.x, PXnew);
        Fp2.copy(P.z, PZnew);
    }

    /**
     * {@code monodromy_i}: compute the biextension monodromy via the cubical
     * arithmetic of P + [2^e] Q. The {@code swapPQ} flag determines whether
     * we use P, Q, ixP (false) or Q, P, ixQ (true).
     */
    private static void monodromyI(GfField field, EcPoint R, PairingParams pairingData, boolean swapPQ)
    {
        Fp2 ixP = Fp2.zero();
        EcPoint P = new EcPoint(), Q = new EcPoint();
        EcPoint PnQ = new EcPoint(), nQ = new EcPoint();

        if (!swapPQ)
        {
            EcPoint.copy(P, pairingData.P);
            EcPoint.copy(Q, pairingData.Q);
            Fp2.copy(ixP, pairingData.ixP);
        }
        else
        {
            EcPoint.copy(P, pairingData.Q);
            EcPoint.copy(Q, pairingData.P);
            Fp2.copy(ixP, pairingData.ixQ);
        }

        biextLadder2e(field, pairingData.e - 1, PnQ, nQ, pairingData.PQ, Q, ixP, pairingData.A24);
        translate(field, PnQ, nQ);
        translate(field, nQ, nQ);
        pointRatio(field, R, PnQ, nQ, P);
    }

    /** Batch-normalise P, Q in {@code pairingData} and cache 1/x(P), 1/x(Q). */
    private static void cubicalNormalization(GfField field, PairingParams pairingData, EcPoint P, EcPoint Q)
    {
        Fp2[] t = new Fp2[]{P.x.copy(), P.z.copy(), Q.x.copy(), Q.z.copy()};
        field.fp2BatchedInv(t, 4);

        field.fp2Mul(pairingData.ixP, P.z, t[0]);
        field.fp2Mul(pairingData.ixQ, Q.z, t[2]);

        field.fp2Mul(pairingData.P.x, P.x, t[1]);
        field.fp2Mul(pairingData.Q.x, Q.x, t[3]);
        Fp2.setOne(pairingData.P.z);
        Fp2.setOne(pairingData.Q.z);
    }

    /** {@code weil_n}: Weil pairing assuming points are pre-normalised. */
    private static void weilN(GfField field, Fp2 r, PairingParams pairingData)
    {
        EcPoint R0 = new EcPoint(), R1 = new EcPoint();
        monodromyI(field, R0, pairingData, true);
        monodromyI(field, R1, pairingData, false);

        field.fp2Mul(r, R0.x, R1.z);
        field.fp2Inv(r);
        field.fp2Mul(r, r, R0.z);
        field.fp2Mul(r, r, R1.x);
    }

    /**
     * Weil pairing {@code e_(2^e)(P, Q)} via the biextension ladder.
     * Crashes (divide-by-zero) if either P or Q is (0 : 1).
     */
    public static void weil(GfField field, Fp2 r, int e, EcPoint P, EcPoint Q, EcPoint PQ, EcCurve E)
    {
        PairingParams pairingData = new PairingParams();
        pairingData.e = e;
        cubicalNormalization(field, pairingData, P, Q);
        EcPoint.copy(pairingData.PQ, PQ);

        EcOps.curveNormalizeA24(E);
        EcPoint.copy(pairingData.A24, E.A24);

        weilN(field, r, pairingData);
    }

    /** {@code fp2_frob}: complex conjugation in Fp². */
    public static void fp2Frob(GfField field, Fp2 out, Fp2 in)
    {
        Fp.copy(out.re, in.re);
        field.fpNeg(out.im, in.im);
    }

    /**
     * {@code clear_cofac}: compute {@code r = a^pCofactorFor2f} on Fp².
     *
     * <p>The C reference does a "shift then square-and-multiply" loop driven
     * by {@code exp = pCofactorFor2f >> 1}; tracing the loop for the lvl1
     * value 5 yields {@code r = a^5}. Algebraically this implements
     * {@code r = a^pCofactorFor2f} whenever {@code pCofactorFor2f} is odd
     * (lvl1: 5). For lvl3 / lvl5 the odd cofactor is also small and the same
     * loop applies; we take it as a {@code long} parameter so this stays
     * level-independent.</p>
     *
     * @param r              output.
     * @param a              base.
     * @param pCofactorFor2f the odd cofactor {@code (p + 1) / 2^TORSION_EVEN_POWER}.
     */
    public static void clearCofac(GfField field, Fp2 r, Fp2 a, long pCofactorFor2f)
    {
        long exp = pCofactorFor2f >>> 1;
        Fp2 x = Fp2.zero();
        Fp2.copy(x, a);
        Fp2.copy(r, a);

        while (exp > 0)
        {
            field.fp2Sqr(r, r);
            if ((exp & 1L) != 0)
            {
                field.fp2Mul(r, r, x);
            }
            exp >>>= 1;
        }
    }
}
