package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;


/**
 * Discrete-logarithm and pairing-based change-of-basis routines.
 *
 * <p>Java mirror of the dlog-side helpers in
 * {@code src/ec/ref/lvlx/biextension.c}: {@code fp2_dlog_2e}, and the
 * higher-level routines that compose into {@code ec_dlog_2_tate} and
 * {@code change_of_basis_matrix_tate}.</p>
 *
 * <p>This file currently hosts only the lowest-level piece,
 * {@link #fp2Dlog2e}. The remaining functions (clear_cofac, reduced_tate,
 * cubical_normalization_dlog, compute_difference_points, tate_dlog_partial,
 * ec_dlog_2_tate) will land incrementally.</p>
 */
final class EcDlog
{
    private EcDlog()
    {
    }

    /**
     * {@code fp2_dlog_2e}: given {@code f, g ∈ F_{p²}^*} with {@code f = g^a}
     * for some {@code 0 ≤ a < 2^e}, recover {@code a}.
     *
     * <p>The {@code gInverse} parameter is the multiplicative inverse of
     * {@code g} (the C reference accepts it pre-computed; we do the same to
     * mirror the prototype). Internally proceeds by Pohlig-Hellman
     * recursion: split the exponent in half, recurse on the high and low
     * halves, combine via {@code a = low + 2^right · high}.</p>
     *
     * @param f         element whose discrete log is being computed.
     * @param gInverse  inverse of the base {@code g}.
     * @param e         exponent (so the order of {@code g} divides {@code 2^e}).
     * @return the recovered exponent, or {@code null} on dlog failure (the
     *         C reference {@code assert}s success; we soften that to a
     *         {@code null} return so callers can react).
     */
    public static BigInteger fp2Dlog2e(GfField field, Fp2 f, Fp2 gInverse, int e)
    {
        if (e <= 0)
        {
            return BigInteger.ZERO;
        }

        // Stack depth: log2(e) + 1 slots is enough for the recursion. The C
        // code uses `log = floor(log2(e)) + 2`; we mirror it.
        int log = 1;
        int len = e;
        while (len > 1)
        {
            len >>= 1;
            log++;
        }
        log += 1;

        Fp2[] powsF = new Fp2[log];
        Fp2[] powsG = new Fp2[log];
        for (int i = 0; i < log; i++)
        {
            powsF[i] = Fp2.zero();
            powsG[i] = Fp2.zero();
        }
        Fp2.copy(powsF[0], f);
        Fp2.copy(powsG[0], gInverse);

        BigInteger[] holder = new BigInteger[1];
        holder[0] = BigInteger.ZERO;
        if (!dlogRec(field, holder, e, powsF, powsG, 1))
        {
            return null;
        }
        return holder[0];
    }

    /**
     * Recursive worker for {@link #fp2Dlog2e}.
     *
     * <p>The C reference passes a {@code digit_t[]} output buffer; here we
     * use a 1-slot {@link BigInteger}{@code []} holder so the caller sees
     * the mutation cleanly. The {@code powsF / powsG} arrays are mutated
     * by the recursion (squarings and multiplications climb the call
     * stack); they are the C reference's "stack" of intermediate values
     * shared across recursive frames.</p>
     */
    private static boolean dlogRec(GfField field, BigInteger[] outA, int len,
                                   Fp2[] powsF, Fp2[] powsG, int stackLen)
    {
        if (len == 0)
        {
            outA[0] = BigInteger.ZERO;
            return true;
        }
        if (len == 1)
        {
            Fp2 fTop = powsF[stackLen - 1];
            Fp2 gTop = powsG[stackLen - 1];
            if (Fp2.isOne(fTop) != 0)
            {
                outA[0] = BigInteger.ZERO;
                // square all lower g entries
                for (int i = 0; i < stackLen - 1; i++)
                {
                    field.fp2Sqr(powsG[i], powsG[i]);
                }
                return true;
            }
            if (Fp2.isEqual(fTop, gTop) != 0)
            {
                outA[0] = BigInteger.ONE;
                // Update all lower-level entries: f *= g, then g = g^2.
                for (int i = 0; i < stackLen - 1; i++)
                {
                    field.fp2Mul(powsF[i], powsF[i], powsG[i]);
                    field.fp2Sqr(powsG[i], powsG[i]);
                }
                return true;
            }
            return false;
        }

        // Split: lower half has `left` bits, upper half has `right` bits.
        // The C reference uses `right = (long)(len * 0.5)`, which is
        // truncation toward zero — for non-negative len that's floor(len/2).
        int right = len / 2;
        int left = len - right;

        // Push: copy stack[stackLen-1] up to stack[stackLen] and square
        // {f, g} `left` times at the top of the stack so the top-of-stack
        // values represent f^{2^left}, g^{2^left}.
        Fp2.copy(powsF[stackLen], powsF[stackLen - 1]);
        Fp2.copy(powsG[stackLen], powsG[stackLen - 1]);
        for (int i = 0; i < left; i++)
        {
            field.fp2Sqr(powsF[stackLen], powsF[stackLen]);
            field.fp2Sqr(powsG[stackLen], powsG[stackLen]);
        }

        BigInteger[] dlp1 = new BigInteger[]{BigInteger.ZERO};
        if (!dlogRec(field, dlp1, right, powsF, powsG, stackLen + 1))
        {
            return false;
        }
        BigInteger[] dlp2 = new BigInteger[]{BigInteger.ZERO};
        if (!dlogRec(field, dlp2, left, powsF, powsG, stackLen))
        {
            return false;
        }
        // a = dlp1 + 2^right · dlp2
        outA[0] = dlp1[0].add(dlp2[0].shiftLeft(right));
        return true;
    }

    // ------------------------------------------------------------------
    // cubical_normalization_dlog
    // ------------------------------------------------------------------

    /**
     * Java mirror of {@code cubical_normalization_dlog} from
     * {@code src/ec/ref/lvlx/biextension.c}: batch-invert eleven Fp2
     * coordinates (P.x, P.z, Q.x, Q.z, P-Q.x, P-Q.z, R.x, R.z, S.x, S.z,
     * curve.C) and normalize all of them in place. Writes the four
     * x-coordinate inverses into {@code params.ixP/Q/R/S} and normalizes
     * the curve to {@code (A/C : 1)}.
     *
     * @param params  in/out: PQ, RS, ixP/Q/R/S, A24 all touched.
     * @param curve   in/out: A and C are normalized (C set to 1).
     */
    private static void cubicalNormalizationDlog(GfField field, PairingDlogParams params, EcCurve curve)
    {
        EcBasis PQ = params.PQ;
        EcBasis RS = params.RS;

        Fp2[] t = new Fp2[11];
        t[0]  = Fp2.zero(); Fp2.copy(t[0],  PQ.P.x);
        t[1]  = Fp2.zero(); Fp2.copy(t[1],  PQ.P.z);
        t[2]  = Fp2.zero(); Fp2.copy(t[2],  PQ.Q.x);
        t[3]  = Fp2.zero(); Fp2.copy(t[3],  PQ.Q.z);
        t[4]  = Fp2.zero(); Fp2.copy(t[4],  PQ.PmQ.x);
        t[5]  = Fp2.zero(); Fp2.copy(t[5],  PQ.PmQ.z);
        t[6]  = Fp2.zero(); Fp2.copy(t[6],  RS.P.x);
        t[7]  = Fp2.zero(); Fp2.copy(t[7],  RS.P.z);
        t[8]  = Fp2.zero(); Fp2.copy(t[8],  RS.Q.x);
        t[9]  = Fp2.zero(); Fp2.copy(t[9],  RS.Q.z);
        t[10] = Fp2.zero(); Fp2.copy(t[10], curve.C);

        field.fp2BatchedInv(t, 11);

        // PQ.P normalised + ixP = P.z · inv(P.x).
        field.fp2Mul(params.ixP, PQ.P.z, t[0]);
        field.fp2Mul(PQ.P.x, PQ.P.x, t[1]);
        Fp2.setOne(PQ.P.z);

        // PQ.Q normalised + ixQ.
        field.fp2Mul(params.ixQ, PQ.Q.z, t[2]);
        field.fp2Mul(PQ.Q.x, PQ.Q.x, t[3]);
        Fp2.setOne(PQ.Q.z);

        // PQ.PmQ normalised. Note the C reference uses t[5] for the x
        // multiplication (NOT t[4]) and does not record an inverse for
        // P-Q — only the basis points have inverses tracked.
        field.fp2Mul(PQ.PmQ.x, PQ.PmQ.x, t[5]);
        Fp2.setOne(PQ.PmQ.z);

        // RS.P normalised + ixR.
        field.fp2Mul(params.ixR, RS.P.z, t[6]);
        field.fp2Mul(RS.P.x, RS.P.x, t[7]);
        Fp2.setOne(RS.P.z);

        // RS.Q normalised + ixS.
        field.fp2Mul(params.ixS, RS.Q.z, t[8]);
        field.fp2Mul(RS.Q.x, RS.Q.x, t[9]);
        Fp2.setOne(RS.Q.z);

        // Curve normalised to (A/C : 1).
        field.fp2Mul(curve.A, curve.A, t[10]);
        Fp2.setOne(curve.C);
    }

    // ------------------------------------------------------------------
    // compute_difference_points
    // ------------------------------------------------------------------

    /**
     * Java mirror of {@code compute_difference_points} from
     * {@code src/ec/ref/lvlx/biextension.c}: given two normalized bases
     * {@code PQ = (P, Q, P-Q)} and {@code RS = (R, S, R-S)} on
     * {@code curve}, compute the four difference x-coordinates
     * {@code x(P-R), x(P-S), x(R-Q), x(S-Q)} into {@code params.diff}.
     *
     * <p>The implementation lifts both bases to Jacobian coordinates via
     * {@link EcBasisOps#liftBasisNormalized}, negates the relevant
     * Jacobian point, adds, then projects back to (X : Z).</p>
     *
     * @param params  in/out: writes the four diff points; expects PQ and
     *                RS to be normalized (i.e. {@code cubicalNormalizationDlog}
     *                already called).
     * @param curve   the Montgomery curve (normalized).
     */
    private static void computeDifferencePoints(GfField field, PairingDlogParams params, EcCurve curve)
    {
        JacPoint xyP = new JacPoint();
        JacPoint xyQ = new JacPoint();
        JacPoint xyR = new JacPoint();
        JacPoint xyS = new JacPoint();
        JacPoint temp = new JacPoint();

        EcJac.init(xyP);
        EcJac.init(xyQ);
        EcJac.init(xyR);
        EcJac.init(xyS);
        EcJac.init(temp);

        EcBasisOps.liftBasisNormalized(field, xyP, xyQ, params.PQ, curve);
        EcBasisOps.liftBasisNormalized(field, xyR, xyS, params.RS, curve);

        // x(P - R) = (P + (-R)).toXz.
        EcJac.neg(field, temp, xyR);
        EcJac.add(field, temp, temp, xyP, curve);
        EcJac.toXz(field, params.diff.PmR, temp);

        // x(P - S).
        EcJac.neg(field, temp, xyS);
        EcJac.add(field, temp, temp, xyP, curve);
        EcJac.toXz(field, params.diff.PmS, temp);

        // x(R - Q).
        EcJac.neg(field, temp, xyQ);
        EcJac.add(field, temp, temp, xyR, curve);
        EcJac.toXz(field, params.diff.RmQ, temp);

        // x(S - Q).
        EcJac.neg(field, temp, xyQ);
        EcJac.add(field, temp, temp, xyS, curve);
        EcJac.toXz(field, params.diff.SmQ, temp);
    }

    // ------------------------------------------------------------------
    // tate_dlog_partial + ec_dlog_2_tate
    // ------------------------------------------------------------------

    /**
     * Result bundle for {@link #ecDlog2Tate}: the four scalars
     * {@code (r1, r2, s1, s2)} satisfying {@code R = r1·P + r2·Q},
     * {@code S = s1·P + s2·Q}.
     */
    public static final class DlogResult
    {
        public BigInteger r1;
        public BigInteger r2;
        public BigInteger s1;
        public BigInteger s2;
    }

    /**
     * Java mirror of {@code tate_dlog_partial} from
     * {@code src/ec/ref/lvlx/biextension.c}: compute four discrete logs
     * across the bases {@code (P, Q)} and {@code (R, S)} via five reduced
     * Tate pairings.
     *
     * <p>The five pairings computed are:</p>
     * <ul>
     *   <li>{@code w_0 = t(P, Q)} — the reference pairing</li>
     *   <li>{@code w_R = t(R, P) = w_0^{r_2}} — solve for r2</li>
     *   <li>{@code w_RQ = t(R, Q) = w_0^{r_1}} — solve for r1</li>
     *   <li>{@code w_S = t(S, P) = w_0^{s_2}} — solve for s2</li>
     *   <li>{@code w_SQ = t(S, Q) = w_0^{s_1}} — solve for s1</li>
     * </ul>
     *
     * <p>After computing the unreduced pairings (in projective {@code (w1/w2)}
     * form), we apply Frobenius and a batched inversion to fold the
     * {@code (p-1)} reduction into a single inverse, then squeeze each
     * value through {@code clear_cofac} and {@code eDiff} squarings to
     * complete the reduction step.</p>
     *
     * @return {@code DlogResult} on success, or {@code null} if any of the
     *         four {@link #fp2Dlog2e} calls failed.
     */
    private static DlogResult tateDlogPartial(GfField field, PairingDlogParams params,
                                             int eFull,
                                             long pCofactorFor2f)
    {
        int eDiff = eFull - params.e;

        // Mutable working copies of the eight points we ladder.
        EcPoint nP = new EcPoint(), nQ = new EcPoint();
        EcPoint nR = new EcPoint(), nS = new EcPoint();
        EcPoint nPQ = new EcPoint();
        EcPoint PnR = new EcPoint(), PnS = new EcPoint();
        EcPoint nRQ = new EcPoint(), nSQ = new EcPoint();

        EcPoint.copy(nP,  params.PQ.P);
        EcPoint.copy(nQ,  params.PQ.Q);
        EcPoint.copy(nR,  params.RS.P);
        EcPoint.copy(nS,  params.RS.Q);
        EcPoint.copy(nPQ, params.PQ.PmQ);
        EcPoint.copy(PnR, params.diff.PmR);
        EcPoint.copy(PnS, params.diff.PmS);
        EcPoint.copy(nRQ, params.diff.RmQ);
        EcPoint.copy(nSQ, params.diff.SmQ);

        // Climb the reference pairing (P, Q) all the way up to 2^(eFull-1) P.
        for (int i = 0; i < eFull - 1; i++)
        {
            EcBiext.cubicalDBLADD(field, nPQ, nP, nPQ, nP, params.ixQ, params.A24);
        }

        // For the four cross-pairings climb to 2^(e-1).
        for (int i = 0; i < params.e - 1; i++)
        {
            EcBiext.cubicalADD(field, PnR, PnR, nR, params.ixP);
            EcBiext.cubicalDBLADD(field, nRQ, nR, nRQ, nR, params.ixQ, params.A24);

            EcBiext.cubicalADD(field, PnS, PnS, nS, params.ixP);
            EcBiext.cubicalDBLADD(field, nSQ, nS, nSQ, nS, params.ixQ, params.A24);
        }

        // Final translates to convert from "(p+T)" to "T" (the cubical -> Tate step).
        EcBiext.translate(field, nPQ, nP);
        EcBiext.translate(field, PnR, nR);
        EcBiext.translate(field, nRQ, nR);
        EcBiext.translate(field, PnS, nS);
        EcBiext.translate(field, nSQ, nS);
        EcBiext.translate(field, nP, nP);
        EcBiext.translate(field, nQ, nQ);
        EcBiext.translate(field, nR, nR);
        EcBiext.translate(field, nS, nS);

        // Compute the five projective pairing values (w1[i] : w2[i]).
        EcPoint T0 = new EcPoint();
        Fp2[] w1 = new Fp2[5];
        Fp2[] w2 = new Fp2[5];
        for (int i = 0; i < 5; i++)
        {
            w1[i] = Fp2.zero();
            w2[i] = Fp2.zero();
        }

        // t(P, Q)^(2^eDiff) = w0.
        EcBiext.pointRatio(field, T0, nPQ, nP, params.PQ.Q);
        Fp2.copy(w1[0], T0.x);
        Fp2.copy(w2[0], T0.z);

        // t(R, P) = w0^{r2}.
        EcBiext.pointRatio(field, T0, PnR, nR, params.PQ.P);
        Fp2.copy(w1[1], T0.x);
        Fp2.copy(w2[1], T0.z);

        // t(R, Q) = w0^{r1}. Note the swap (w2 ← T0.x, w1 ← T0.z) so the
        // dlog target ends up as (T0.z : T0.x) — matching the C reference.
        EcBiext.pointRatio(field, T0, nRQ, nR, params.PQ.Q);
        Fp2.copy(w2[2], T0.x);
        Fp2.copy(w1[2], T0.z);

        // t(S, P) = w0^{s2}.
        EcBiext.pointRatio(field, T0, PnS, nS, params.PQ.P);
        Fp2.copy(w1[3], T0.x);
        Fp2.copy(w2[3], T0.z);

        // t(S, Q) = w0^{s1}. Same swap as t(R, Q).
        EcBiext.pointRatio(field, T0, nSQ, nS, params.PQ.Q);
        Fp2.copy(w2[4], T0.x);
        Fp2.copy(w1[4], T0.z);

        // Batched reduction using projective representation.
        for (int i = 0; i < 5; i++)
        {
            Fp2 frob = Fp2.zero();
            Fp2 tmp = Fp2.zero();
            Fp2.copy(tmp, w1[i]);
            EcBiext.fp2Frob(field, frob, w1[i]);
            field.fp2Mul(w1[i], w2[i], frob);

            EcBiext.fp2Frob(field, frob, w2[i]);
            field.fp2Mul(w2[i], tmp, frob);
        }

        // Batched inversion.
        field.fp2BatchedInv(w2, 5);
        for (int i = 0; i < 5; i++)
        {
            field.fp2Mul(w1[i], w1[i], w2[i]);
        }

        // Final cofactor + eDiff squarings.
        for (int i = 0; i < 5; i++)
        {
            EcBiext.clearCofac(field, w1[i], w1[i], pCofactorFor2f);
            for (int j = 0; j < eDiff; j++)
            {
                field.fp2Sqr(w1[i], w1[i]);
            }
        }

        DlogResult res = new DlogResult();
        res.r2 = fp2Dlog2e(field, w1[1], w1[0], params.e);
        res.r1 = fp2Dlog2e(field, w1[2], w1[0], params.e);
        res.s2 = fp2Dlog2e(field, w1[3], w1[0], params.e);
        res.s1 = fp2Dlog2e(field, w1[4], w1[0], params.e);
        if (res.r1 == null || res.r2 == null || res.s1 == null || res.s2 == null)
        {
            return null;
        }
        return res;
    }

    /**
     * {@code ec_dlog_2_tate}: given a full 2^TORSION_EVEN_POWER-torsion
     * basis {@code (P, Q)} on {@code curve} and a 2^e-torsion basis
     * {@code (R, S)} on the same curve, return the four scalars
     * {@code (r1, r2, s1, s2)} satisfying
     * {@code R = r1·P + r2·Q} and {@code S = s1·P + s2·Q}.
     *
     * <p>Java mirror of {@code ec_dlog_2_tate} from
     * {@code src/ec/ref/lvlx/biextension.c}.</p>
     *
     * @param PQ                 the full 2^TORSION_EVEN_POWER-torsion basis
     *                           on {@code curve}.
     * @param RS                 the 2^e-torsion basis to decompose.
     * @param curve              the Montgomery curve (A24 will be cached).
     * @param e                  power of two specifying RS's torsion.
     * @param torsionEvenPower   {@code TORSION_EVEN_POWER}.
     * @param pCofactorFor2f     odd cofactor {@code (p + 1) / 2^TORSION_EVEN_POWER}.
     * @return four scalars, or {@code null} on dlog failure.
     */
    public static DlogResult ecDlog2Tate(GfField field, EcBasis PQ, EcBasis RS, EcCurve curve, int e,
                                         int torsionEvenPower, long pCofactorFor2f)
    {
        EcOps.normalizeCurveAndA24(curve);

        PairingDlogParams params = new PairingDlogParams();
        params.e = e;
        EcBasis.copy(params.PQ, PQ);
        EcBasis.copy(params.RS, RS);
        EcPoint.copy(params.A24, curve.A24);

        cubicalNormalizationDlog(field, params, curve);
        computeDifferencePoints(field, params, curve);

        return tateDlogPartial(field, params, torsionEvenPower, pCofactorFor2f);
    }

    // ------------------------------------------------------------------
    // change_of_basis_matrix_tate
    // ------------------------------------------------------------------

    /**
     * {@code change_of_basis_matrix_tate}: given two bases {@code B1} and
     * {@code B2} of the {@code 2^f}-torsion, compute the 2×2 integer matrix
     * {@code M} such that {@code M · B2 = B1} (componentwise). Java mirror
     * of {@code change_of_basis_matrix_tate} in
     * {@code src/id2iso/ref/lvlx/id2iso.c}.
     *
     * <p>The {@code invert} variant swaps the role of {@code B1} and
     * {@code B2} and inverts the resulting matrix modulo {@code 2^f}.</p>
     *
     * @param B1                 first basis (used as "RS" in the dlog).
     * @param B2                 second basis (must be a full 2^TORSION_EVEN_POWER
     *                           basis; used as "PQ").
     * @param E                  the curve.
     * @param f                  torsion exponent.
     * @param torsionEvenPower   {@code TORSION_EVEN_POWER}.
     * @param pCofactorFor2f     odd cofactor.
     * @return the 4-entry result as a flat {@code [[m00, m01], [m10, m11]]}
     *         {@code BigInteger[][]} matrix, or {@code null} on dlog failure.
     */
    public static BigInteger[][] changeOfBasisMatrixTate(GfField field, EcBasis B1, EcBasis B2,
                                                        EcCurve E, int f,
                                                        int torsionEvenPower,
                                                        long pCofactorFor2f)
    {
        // Non-invert: dlog of B1 against B2.
        DlogResult dlog = ecDlog2Tate(field, B2, B1, E, f, torsionEvenPower, pCofactorFor2f);
        if (dlog == null)
        {
            return null;
        }
        BigInteger[][] m = new BigInteger[2][2];
        m[0][0] = dlog.r1;
        m[1][0] = dlog.r2;
        m[0][1] = dlog.s1;
        m[1][1] = dlog.s2;
        return m;
    }

    /**
     * {@code change_of_basis_matrix_tate_invert}: as
     * {@link #changeOfBasisMatrixTate(EcBasis, EcBasis, EcCurve, int, int, long)}
     * but with {@code B1} as the full 2^TORSION_EVEN_POWER basis, then
     * inverts the resulting matrix mod {@code 2^f}.
     */
    public static BigInteger[][] changeOfBasisMatrixTateInvert(GfField field, EcBasis B1, EcBasis B2,
                                                               EcCurve E, int f,
                                                               int torsionEvenPower,
                                                               long pCofactorFor2f)
    {
        DlogResult dlog = ecDlog2Tate(field, B1, B2, E, f, torsionEvenPower, pCofactorFor2f);
        if (dlog == null)
        {
            return null;
        }
        BigInteger[][] m = new BigInteger[2][2];
        m[0][0] = dlog.r1;
        m[1][0] = dlog.r2;
        m[0][1] = dlog.s1;
        m[1][1] = dlog.s2;

        // Invert m mod 2^f. The C reference uses mp_invert_matrix; for the
        // BigInteger view, det · M^{-1} = adj(M), then multiply by det^{-1}.
        BigInteger mod = BigInteger.ONE.shiftLeft(f);
        BigInteger det = m[0][0].multiply(m[1][1]).subtract(m[0][1].multiply(m[1][0])).mod(mod);
        BigInteger detInv;
        try
        {
            detInv = det.modInverse(mod);
        }
        catch (ArithmeticException e)
        {
            return null;
        }
        BigInteger[][] inv = new BigInteger[2][2];
        inv[0][0] =  m[1][1].multiply(detInv).mod(mod);
        inv[0][1] = mod.subtract(m[0][1]).multiply(detInv).mod(mod);
        inv[1][0] = mod.subtract(m[1][0]).multiply(detInv).mod(mod);
        inv[1][1] =  m[0][0].multiply(detInv).mod(mod);
        return inv;
    }


    public static BigInteger[][] changeOfBasisMatrixTate(EcBasis B1, EcBasis B2,
                                                        EcCurve E, int f,
                                                        int torsionEvenPower,
                                                        long pCofactorFor2f)
    {
        return changeOfBasisMatrixTate(E.field, B1, B2, E, f, torsionEvenPower, pCofactorFor2f);
    }

    public static BigInteger[][] changeOfBasisMatrixTateInvert(EcBasis B1, EcBasis B2,
                                                               EcCurve E, int f,
                                                               int torsionEvenPower,
                                                               long pCofactorFor2f)
    {
        return changeOfBasisMatrixTateInvert(E.field, B1, B2, E, f, torsionEvenPower, pCofactorFor2f);
    }
}
