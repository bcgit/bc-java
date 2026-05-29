package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Isogeny-chain evaluation, x-only isomorphisms, and small-chain naive
 * isogeny composition. Java port of {@code src/ec/ref/lvlx/isog_chains.c}.
 */
final class EcIsogChains
{
    private EcIsogChains()
    {
    }

    /**
     * Depth-first 4-isogeny chain evaluator. The C reference splits the
     * isogeny chain using a binary stack. Returns 0 on success, -1 if the
     * kernel was malformed (e.g. wrong torsion order, special isogeny not
     * allowed).
     */
    private static int evalEvenStrategy(GfField field, EcCurve curve, EcPoint[] points, int lenPoints,
                                       EcPoint kernel, int isogLen)
    {
        EcOps.curveNormalizeA24(field, curve);
        EcPoint A24 = curve.A24.copy();

        // The C uses ⌈log₂(isogLen)⌉ + 1 stack slots.
        int space = 1;
        for (int i = 1; i < isogLen; i *= 2)
        {
            space++;
        }
        EcPoint[] splits = new EcPoint[space];
        int[] todo = new int[space];
        for (int i = 0; i < space; i++)
        {
            splits[i] = new EcPoint();
        }
        EcPoint.copy(splits[0], kernel);
        todo[0] = isogLen;

        int current = 0;

        for (int j = 0; j < isogLen / 2; j++)
        {
            // Walk down until we find a point of order 4.
            while (todo[current] != 2)
            {
                current++;
                EcPoint.copy(splits[current], splits[current - 1]);
                int numDbls = todo[current - 1] / 4 * 2 + todo[current - 1] % 2;
                todo[current] = todo[current - 1] - numDbls;
                while (numDbls-- > 0)
                {
                    EcArith.xDBL_A24(field, splits[current], splits[current], A24, false);
                }
            }

            if (j == 0)
            {
                if (EcOps.isFourTorsion(field, splits[current], curve) == 0)
                {
                    return -1;
                }
                EcPoint T = new EcPoint();
                EcArith.xDBL_A24(field, T, splits[current], A24, false);
                if (Fp2.isZero(T.x) != 0)
                {
                    return -1; // special isogeny disallowed
                }
            }

            // 4-isogeny
            EcKps4 kps4 = new EcKps4();
            EcIsog.xisog_4(field, kps4, A24, splits[current]);
            EcIsog.xeval_4(field, splits, splits, current, kps4);
            for (int i = 0; i < current; i++)
            {
                todo[i] -= 2;
            }
            EcIsog.xeval_4(field, points, points, lenPoints, kps4);

            current--;
        }

        // Trailing 2-isogeny when length is odd.
        if ((isogLen & 1) != 0)
        {
            if (isogLen == 1 && EcOps.isTwoTorsion(field, splits[0], curve) == 0)
            {
                return -1;
            }
            if (Fp2.isZero(splits[0].x) != 0)
            {
                return -1;
            }
            EcKps2 kps2 = new EcKps2();
            EcIsog.xisog_2(field, kps2, A24, splits[0]);
            EcIsog.xeval_2(field, points, points, lenPoints, kps2);
        }

        EcOps.a24ToAc(field, curve, A24);
        curve.isA24ComputedAndNormalized = false;
        return 0;
    }

    /** {@code ec_eval_even}: wrapper around {@link #evalEvenStrategy}. */
    public static int evalEven(GfField field, EcCurve image, EcIsogEven phi, EcPoint[] points, int lenPoints)
    {
        EcCurve.copy(image, phi.curve);
        return evalEvenStrategy(field, image, points, lenPoints, phi.kernel, phi.length);
    }

    /**
     * Naive 2-isogeny chain. Walks the kernel down by doubling, then applies
     * a degree-2 step at each level. The {@code special} flag enables the
     * (0 : 1) kernel case.
     */
    public static int evalSmallChain(GfField field, EcCurve curve, EcPoint kernel, int len,
                                     EcPoint[] points, int lenPoints, boolean special)
    {
        EcPoint A24 = new EcPoint();
        EcOps.acToA24(field, A24, curve);

        EcKps2 kps = new EcKps2();
        EcPoint smallK = new EcPoint();
        EcPoint bigK = kernel.copy();

        for (int i = 0; i < len; i++)
        {
            EcPoint.copy(smallK, bigK);
            for (int jj = 0; jj < len - i - 1; jj++)
            {
                EcArith.xDBL_A24(field, smallK, smallK, A24, false);
            }
            if (i == 0 && EcOps.isTwoTorsion(field, smallK, curve) == 0)
            {
                return -1;
            }
            if (Fp2.isZero(smallK.x) != 0)
            {
                if (special)
                {
                    EcPoint B24 = new EcPoint();
                    EcIsog.xisog_2_singular(field, kps, B24, A24);
                    EcPoint[] bigKArr = new EcPoint[]{bigK};
                    EcIsog.xeval_2_singular(field, bigKArr, bigKArr, 1, kps);
                    EcIsog.xeval_2_singular(field, points, points, lenPoints, kps);
                    EcPoint.copy(A24, B24);
                }
                else
                {
                    return -1;
                }
            }
            else
            {
                EcIsog.xisog_2(field, kps, A24, smallK);
                EcPoint[] bigKArr = new EcPoint[]{bigK};
                EcIsog.xeval_2(field, bigKArr, bigKArr, 1, kps);
                EcIsog.xeval_2(field, points, points, lenPoints, kps);
            }
        }
        EcOps.a24ToAc(field, curve, A24);
        curve.isA24ComputedAndNormalized = false;
        return 0;
    }

    /**
     * {@code ec_isomorphism}: compute the isomorphism (X : Z) ↦ (Nx X + Nz Z : D Z)
     * that maps Montgomery curve {@code from} to {@code to}. Returns nonzero
     * iff Nx or D are zero (invalid output).
     */
    public static int isomorphism(GfField field, EcIsom isom, EcCurve from, EcCurve to)
    {
        Fp2 t0 = Fp2.zero(), t1 = Fp2.zero();
        Fp2 t2 = Fp2.zero(), t3 = Fp2.zero(), t4 = Fp2.zero();

        field.fp2Mul(t0, from.A, from.C);
        field.fp2Mul(t1, to.A, to.C);

        field.fp2Mul(t2, t1, to.C);
        field.fp2Add(t3, t2, t2);
        field.fp2Add(t3, t3, t3);
        field.fp2Add(t3, t3, t3);
        field.fp2Add(t2, t2, t3);
        field.fp2Sqr(t3, to.A);
        field.fp2Mul(t3, t3, to.A);
        field.fp2Add(t3, t3, t3);
        field.fp2Sub(isom.Nx, t3, t2);
        field.fp2Mul(t2, t0, from.A);
        field.fp2Sqr(t3, from.C);
        field.fp2Mul(t3, t3, from.C);
        field.fp2Add(t4, t3, t3);
        field.fp2Add(t3, t4, t3);
        field.fp2Sub(t3, t3, t2);
        field.fp2Mul(isom.Nx, isom.Nx, t3);

        field.fp2Mul(t2, t0, from.C);
        field.fp2Add(t3, t2, t2);
        field.fp2Add(t3, t3, t3);
        field.fp2Add(t3, t3, t3);
        field.fp2Add(t2, t2, t3);
        field.fp2Sqr(t3, from.A);
        field.fp2Mul(t3, t3, from.A);
        field.fp2Add(t3, t3, t3);
        field.fp2Sub(isom.D, t3, t2);
        field.fp2Mul(t2, t1, to.A);
        field.fp2Sqr(t3, to.C);
        field.fp2Mul(t3, t3, to.C);
        field.fp2Add(t4, t3, t3);
        field.fp2Add(t3, t4, t3);
        field.fp2Sub(t3, t3, t2);
        field.fp2Mul(isom.D, isom.D, t3);

        field.fp2Mul(t0, to.C, from.A);
        field.fp2Mul(t0, t0, isom.Nx);
        field.fp2Mul(t1, from.C, to.A);
        field.fp2Mul(t1, t1, isom.D);
        field.fp2Sub(isom.Nz, t0, t1);
        field.fp2Mul(t0, from.C, to.C);
        field.fp2Add(t1, t0, t0);
        field.fp2Add(t0, t0, t1);
        field.fp2Mul(isom.D, isom.D, t0);
        field.fp2Mul(isom.Nx, isom.Nx, t0);

        return Fp2.isZero(isom.Nx) | Fp2.isZero(isom.D);
    }

    /** {@code ec_iso_eval}: evaluate the isomorphism on a projective point. */
    public static void isoEval(GfField field, EcPoint P, EcIsom isom)
    {
        Fp2 tmp = Fp2.zero();
        field.fp2Mul(P.x, P.x, isom.Nx);
        field.fp2Mul(tmp, P.z, isom.Nz);
        field.fp2Add(P.x, P.x, tmp);
        field.fp2Mul(P.z, P.z, isom.D);
    }

    // ------------------------------------------------------------------
    // Field-from-curve convenience overloads (see EcLadder for rationale).
    // {@code isoEval} keeps its lvl1 default since {@link EcIsom} carries no
    // curve; callers on non-lvl1 paths must pass an explicit field.
    // ------------------------------------------------------------------

    public static int evalEven(EcCurve image, EcIsogEven phi, EcPoint[] points, int lenPoints)
    {
        return evalEven(phi.curve.field, image, phi, points, lenPoints);
    }

    public static int evalSmallChain(EcCurve curve, EcPoint kernel, int len,
                                     EcPoint[] points, int lenPoints, boolean special)
    {
        return evalSmallChain(curve.field, curve, kernel, len, points, lenPoints, special);
    }

    public static int isomorphism(EcIsom isom, EcCurve from, EcCurve to)
    {
        return isomorphism(from.field, isom, from, to);
    }
}

