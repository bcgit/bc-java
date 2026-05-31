package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;


/**
 * Biscalar Montgomery ladder (k·P + l·Q) and the high-level
 * {@code ec_biscalar_mul} wrapper. Java port of {@code xDBLMUL} and
 * {@code ec_biscalar_mul} from {@code src/ec/ref/lvlx/ec.c}.
 *
 * <p>Scalars are passed as {@link BigInteger}; the digit-array bit-shift and
 * select_ct/swap_ct primitives in the C are replaced with direct
 * {@code BigInteger.testBit} / {@code shiftRight} / branchy {@code if}s. The
 * algorithm is otherwise mechanically identical to the C reference.</p>
 */
final class EcBiLadder
{
    private EcBiLadder()
    {
    }

    /**
     * {@code xDBLMUL}: S ← k·P + l·Q given the basis (P, Q, P-Q) and the
     * normalised curve (A24 must be (·, 1)).
     *
     * @return 0 if differential-addition formulas are invalid (one of P, Q,
     *         P-Q has a zero coordinate, or P+Q hits one); 1 on success.
     */
    private static int xDBLMUL(EcPoint S, EcPoint P, BigInteger k,
                              EcPoint Q, BigInteger l, EcPoint PQ,
                              int kbits, EcCurve curve)
    {
        if (EcOps.hasZeroCoordinate(P) != 0
            || EcOps.hasZeroCoordinate(Q) != 0
            || EcOps.hasZeroCoordinate(PQ) != 0)
        {
            return 0;
        }

        // Parities and sigma initialisation.
        int bitk0 = k.testBit(0) ? 1 : 0;
        int bitl0 = l.testBit(0) ? 1 : 0;
        int[] sigma = new int[2];
        sigma[0] = bitk0 ^ 1;
        sigma[1] = bitl0 ^ 1;
        int evens = sigma[0] + sigma[1];
        int mevens = -(evens & 1);  // 0 if both even or both odd, else 0xFFFFFFFF

        // If both even or both odd, pick sigma = (0, 1).
        sigma[0] = sigma[0] & mevens;
        sigma[1] = (sigma[1] & mevens) | (1 & ~mevens);

        // Convert even scalars to odd by subtracting 1.
        BigInteger kT = bitk0 == 0 ? k.subtract(BigInteger.ONE) : k;
        BigInteger lT = bitl0 == 0 ? l.subtract(BigInteger.ONE) : l;

        // Scalar recoding into r[2i], r[2i+1] bits.
        int[] r = new int[2 * kbits];
        int preSigma = 0;
        for (int i = 0; i < kbits; i++)
        {
            // If sigma[0] != preSigma, swap kT and lT.
            if ((sigma[0] ^ preSigma) != 0)
            {
                BigInteger tmp = kT;
                kT = lT;
                lT = tmp;
            }

            int bs1Ip1, bs2Ip1;
            if (i == kbits - 1)
            {
                bs1Ip1 = 0;
                bs2Ip1 = 0;
            }
            else
            {
                // C mp_shiftr returns OLD bit 0 (the LSB shifted out), then shifts.
                bs1Ip1 = kT.testBit(0) ? 1 : 0;
                bs2Ip1 = lT.testBit(0) ? 1 : 0;
                kT = kT.shiftRight(1);
                lT = lT.shiftRight(1);
            }
            int bs1I = kT.testBit(0) ? 1 : 0;
            int bs2I = lT.testBit(0) ? 1 : 0;

            r[2 * i] = bs1I ^ bs1Ip1;
            r[2 * i + 1] = bs2I ^ bs2Ip1;

            // Revert sigma if r[2i+1] is 1.
            preSigma = sigma[0];
            if (r[2 * i + 1] != 0)
            {
                int t = sigma[0];
                sigma[0] = sigma[1];
                sigma[1] = t;
            }
        }

        EcPoint[] R = new EcPoint[]{new EcPoint(), new EcPoint(), new EcPoint()};
        EcOps.pointInit(R[0]);
        EcOps.selectPoint(R[1], P, Q, -sigma[0]);
        EcOps.selectPoint(R[2], Q, P, -sigma[0]);

        EcPoint DIFF1a = R[1].copy();
        EcPoint DIFF1b = R[2].copy();

        final GfField field = curve.field;

        // R[2] ← P + Q via xADD.
        EcArith.xADD(field, R[2], R[1], R[2], PQ);
        if (EcOps.hasZeroCoordinate(R[2]) != 0)
        {
            return 0;
        }

        EcPoint DIFF2a = R[2].copy();
        EcPoint DIFF2b = PQ.copy();

        boolean AIsZero = Fp2.isZero(curve.A) != 0;
        EcPoint[] T = new EcPoint[]{new EcPoint(), new EcPoint(), new EcPoint()};

        for (int i = kbits - 1; i >= 0; i--)
        {
            int h = r[2 * i] + r[2 * i + 1];        // in {0, 1, 2}
            int maskk;

            maskk = -(h & 1);
            EcOps.selectPoint(T[0], R[0], R[1], maskk);
            maskk = -(h >> 1);
            EcOps.selectPoint(T[0], T[0], R[2], maskk);
            if (AIsZero)
            {
                EcArith.xDBL_E0(field, T[0], T[0]);
            }
            else
            {
                EcArith.xDBL_A24(field, T[0], T[0], curve.A24, true);
            }

            maskk = -r[2 * i + 1];
            EcOps.selectPoint(T[1], R[0], R[1], maskk);
            EcOps.selectPoint(T[2], R[1], R[2], maskk);

            if (r[2 * i + 1] != 0)
            {
                EcOps.cswapPoints(DIFF1a, DIFF1b, -1);
            }
            EcArith.xADD(field, T[1], T[1], T[2], DIFF1a);
            EcArith.xADD(field, T[2], R[0], R[2], DIFF2a);

            if ((h & 1) != 0)
            {
                EcOps.cswapPoints(DIFF2a, DIFF2b, -1);
            }

            EcPoint.copy(R[0], T[0]);
            EcPoint.copy(R[1], T[1]);
            EcPoint.copy(R[2], T[2]);
        }

        EcOps.selectPoint(S, R[0], R[1], mevens);
        int maskk = -(bitk0 & bitl0);
        EcOps.selectPoint(S, S, R[2], maskk);
        return 1;
    }

    /**
     * {@code ec_biscalar_mul}: combined scalar mul k·P + l·Q on a torsion basis.
     * Handles the kbits == 1 edge case by table lookup. Returns 0 on bad input.
     */
    public static int biscalarMul(EcPoint res, BigInteger scalarP, BigInteger scalarQ,
                                  int kbits, EcBasis PQ, EcCurve curve)
    {
        if (Fp2.isZero(PQ.PmQ.z) != 0)
        {
            return 0;
        }
        if (kbits == 1)
        {
            if (EcOps.isTwoTorsion(PQ.P, curve) == 0
                || EcOps.isTwoTorsion(PQ.Q, curve) == 0
                || EcOps.isTwoTorsion(PQ.PmQ, curve) == 0)
            {
                return 0;
            }
            int bP = scalarP.testBit(0) ? 1 : 0;
            int bQ = scalarQ.testBit(0) ? 1 : 0;
            if (bP == 0 && bQ == 0)
            {
                EcOps.pointInit(res);
            }
            else if (bP == 1 && bQ == 0)
            {
                EcPoint.copy(res, PQ.P);
            }
            else if (bP == 0)
            {
                EcPoint.copy(res, PQ.Q);
            }
            else
            {
                EcPoint.copy(res, PQ.PmQ);
            }
            return 1;
        }
        EcCurve E = curve.copy();
        if (Fp2.isZero(curve.A) == 0)
        {
            EcOps.curveNormalizeA24(E);
        }
        return xDBLMUL(res, PQ.P, scalarP, PQ.Q, scalarQ, PQ.PmQ, kbits, E);
    }
}
