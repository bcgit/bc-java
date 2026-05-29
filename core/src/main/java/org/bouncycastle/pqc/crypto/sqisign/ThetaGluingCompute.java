package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Java port of the gluing pipeline from {@code src/hd/ref/lvlx/theta_isogenies.c}:
 * {@code action_by_translation_z_and_det}, {@code action_by_translation_compute_matrix},
 * {@code verify_two_torsion}, {@code action_by_translation},
 * {@code gluing_change_of_basis}, {@code gluing_compute}.
 *
 * <p>All level-independent — uses only Fp2/EC/HD ops. The output gluing
 * structure carries the basis-change matrix M (4×4 Fp2), the codomain theta
 * point, the per-isogeny precomputation vector for evaluation, and the
 * 8-torsion image of K1_8 in compact form.</p>
 */
final class ThetaGluingCompute
{
    private ThetaGluingCompute()
    {
    }

    /**
     * {@code action_by_translation_z_and_det}: for the 4-torsion point P4
     * and its double P2 = [2]P4, store P4.z (to be inverted) and the
     * determinant {@code det = P4.x * P2.z - P4.z * P2.x}.
     */
    public static void zAndDet(GfField field, Fp2 zInv, Fp2 detInv, EcPoint P4, EcPoint P2)
    {
        Fp2 tmp = Fp2.zero();
        Fp2.copy(zInv, P4.z);
        field.fp2Mul(detInv, P4.x, P2.z);
        field.fp2Mul(tmp, P4.z, P2.x);
        field.fp2Sub(detInv, detInv, tmp);
    }

    /**
     * {@code action_by_translation_compute_matrix}: build the 2×2 translation
     * matrix G for the action of [2]P4 = P2 on the theta double cover.
     */
    public static void computeTranslationMatrix(GfField field, TranslationMatrix G, EcPoint P4, EcPoint P2,
                                                Fp2 zInv, Fp2 detInv)
    {
        Fp2 tmp = Fp2.zero();

        // G.g10 = P4.x * P2.x * detInv - P4.x / P4.z
        field.fp2Mul(tmp, P4.x, zInv);
        field.fp2Mul(G.g10, P4.x, P2.x);
        field.fp2Mul(G.g10, G.g10, detInv);
        field.fp2Sub(G.g10, G.g10, tmp);

        // G.g11 = P2.x * detInv * P4.z
        field.fp2Mul(G.g11, P2.x, detInv);
        field.fp2Mul(G.g11, G.g11, P4.z);

        // G.g00 = -G.g11
        field.fp2Neg(G.g00, G.g11);

        // G.g01 = -P2.z * detInv * P4.z
        field.fp2Mul(G.g01, P2.z, detInv);
        field.fp2Mul(G.g01, G.g01, P4.z);
        field.fp2Neg(G.g01, G.g01);
    }

    /**
     * {@code verify_two_torsion}: confirms K1_2 and K2_2 are non-zero,
     * independent, and have order exactly 2 (so that [2]Ki_2 = ∞).
     * Returns 1 if the basis is well-formed, 0 otherwise.
     */
    public static int verifyTwoTorsion(GfField field, ThetaCouplePoint K1_2, ThetaCouplePoint K2_2,
                                       ThetaCoupleCurve E12)
    {
        if ((EcOps.isZero(K1_2.P1) | EcOps.isZero(K1_2.P2)
            | EcOps.isZero(K2_2.P1) | EcOps.isZero(K2_2.P2)) != 0)
        {
            return 0;
        }
        if ((EcOps.isEqual(field, K1_2.P1, K2_2.P1) | EcOps.isEqual(field, K1_2.P2, K2_2.P2)) != 0)
        {
            return 0;
        }
        ThetaCouplePoint O1 = new ThetaCouplePoint();
        ThetaCouplePoint O2 = new ThetaCouplePoint();
        HdOps.doubleCouplePoint(O1, K1_2, E12);
        HdOps.doubleCouplePoint(O2, K2_2, E12);
        if ((EcOps.isZero(O1.P1) & EcOps.isZero(O1.P2)
            & EcOps.isZero(O2.P1) & EcOps.isZero(O2.P2)) == 0)
        {
            return 0;
        }
        return 1;
    }

    /**
     * {@code action_by_translation}: compute the four translation matrices
     * Gi[0..3] from the 4-torsion kernel (K1_4, K2_4). Uses batched
     * inversion of 8 Fp² values to avoid 8 separate {@link Fp2Lvl1#inv} calls.
     */
    private static int actionByTranslation(GfField field, TranslationMatrix[] Gi, ThetaCouplePoint K1_4,
                                          ThetaCouplePoint K2_4, ThetaCoupleCurve E12)
    {
        // [2] K1_4 and [2] K2_4 — 2-torsion below the 4-torsion.
        ThetaCouplePoint K1_2 = new ThetaCouplePoint();
        ThetaCouplePoint K2_2 = new ThetaCouplePoint();
        HdOps.doubleCouplePoint(K1_2, K1_4, E12);
        HdOps.doubleCouplePoint(K2_2, K2_4, E12);

        if (verifyTwoTorsion(field, K1_2, K2_2, E12) == 0)
        {
            return 0;
        }

        Fp2[] inverses = new Fp2[]{
            Fp2.zero(), Fp2.zero(), Fp2.zero(), Fp2.zero(),
            Fp2.zero(), Fp2.zero(), Fp2.zero(), Fp2.zero()
        };
        zAndDet(field, inverses[0], inverses[4], K1_4.P1, K1_2.P1);
        zAndDet(field, inverses[1], inverses[5], K1_4.P2, K1_2.P2);
        zAndDet(field, inverses[2], inverses[6], K2_4.P1, K2_2.P1);
        zAndDet(field, inverses[3], inverses[7], K2_4.P2, K2_2.P2);

        field.fp2BatchedInv(inverses, 8);
        if (Fp2.isZero(inverses[0]) != 0)
        {
            return 0;
        }

        computeTranslationMatrix(field, Gi[0], K1_4.P1, K1_2.P1, inverses[0], inverses[4]);
        computeTranslationMatrix(field, Gi[1], K1_4.P2, K1_2.P2, inverses[1], inverses[5]);
        computeTranslationMatrix(field, Gi[2], K2_4.P1, K2_2.P1, inverses[2], inverses[6]);
        computeTranslationMatrix(field, Gi[3], K2_4.P2, K2_2.P2, inverses[3], inverses[7]);
        return 1;
    }

    /**
     * {@code gluing_change_of_basis}: compute the 4×4 basis-change matrix M
     * from the 4-torsion kernel. Returns 0 if the kernel order is not 4.
     */
    private static int gluingChangeOfBasis(GfField field, BasisChangeMatrix M, ThetaCouplePoint K1_4,
                                          ThetaCouplePoint K2_4, ThetaCoupleCurve E12)
    {
        TranslationMatrix[] Gi = new TranslationMatrix[]{
            new TranslationMatrix(), new TranslationMatrix(),
            new TranslationMatrix(), new TranslationMatrix()
        };
        if (actionByTranslation(field, Gi, K1_4, K2_4, E12) == 0)
        {
            return 0;
        }

        Fp2 t001 = Fp2.zero(), t101 = Fp2.zero();
        Fp2 t002 = Fp2.zero(), t102 = Fp2.zero();
        Fp2 tmp = Fp2.zero();

        // First-column products for M11·M21 and M12·M22.
        field.fp2Mul(t001, Gi[0].g00, Gi[2].g00);
        field.fp2Mul(tmp, Gi[0].g01, Gi[2].g10);
        field.fp2Add(t001, t001, tmp);

        field.fp2Mul(t101, Gi[0].g10, Gi[2].g00);
        field.fp2Mul(tmp, Gi[0].g11, Gi[2].g10);
        field.fp2Add(t101, t101, tmp);

        field.fp2Mul(t002, Gi[1].g00, Gi[3].g00);
        field.fp2Mul(tmp, Gi[1].g01, Gi[3].g10);
        field.fp2Add(t002, t002, tmp);

        field.fp2Mul(t102, Gi[1].g10, Gi[3].g00);
        field.fp2Mul(tmp, Gi[1].g11, Gi[3].g10);
        field.fp2Add(t102, t102, tmp);

        // First row of M: traces of the four 4-torsion translation actions.
        Fp2.setOne(M.m[0][0]);
        field.fp2Mul(tmp, t001, t002);
        field.fp2Add(M.m[0][0], M.m[0][0], tmp);
        field.fp2Mul(tmp, Gi[2].g00, Gi[3].g00);
        field.fp2Add(M.m[0][0], M.m[0][0], tmp);
        field.fp2Mul(tmp, Gi[0].g00, Gi[1].g00);
        field.fp2Add(M.m[0][0], M.m[0][0], tmp);

        field.fp2Mul(M.m[0][1], t001, t102);
        field.fp2Mul(tmp, Gi[2].g00, Gi[3].g10);
        field.fp2Add(M.m[0][1], M.m[0][1], tmp);
        field.fp2Mul(tmp, Gi[0].g00, Gi[1].g10);
        field.fp2Add(M.m[0][1], M.m[0][1], tmp);

        field.fp2Mul(M.m[0][2], t101, t002);
        field.fp2Mul(tmp, Gi[2].g10, Gi[3].g00);
        field.fp2Add(M.m[0][2], M.m[0][2], tmp);
        field.fp2Mul(tmp, Gi[0].g10, Gi[1].g00);
        field.fp2Add(M.m[0][2], M.m[0][2], tmp);

        field.fp2Mul(M.m[0][3], t101, t102);
        field.fp2Mul(tmp, Gi[2].g10, Gi[3].g10);
        field.fp2Add(M.m[0][3], M.m[0][3], tmp);
        field.fp2Mul(tmp, Gi[0].g10, Gi[1].g10);
        field.fp2Add(M.m[0][3], M.m[0][3], tmp);

        // Second row: action of (0, K2_4.P2).
        for (int col = 0; col < 4; col++)
        {
            int otherCol = col ^ 1;
            field.fp2Mul(tmp, Gi[3].g01, M.m[0][otherCol]);
            field.fp2Mul(M.m[1][col],
                (col & 1) == 0 ? Gi[3].g00 : Gi[3].g10, M.m[0][col & ~1]);
            field.fp2Add(M.m[1][col], M.m[1][col], tmp);
            // Same shape as the row-1 cases in the C reference: for col = 0:
            //   M[1][0] = Gi[3].g00 * M[0][0] + Gi[3].g01 * M[0][1]
            // for col = 1:
            //   M[1][1] = Gi[3].g10 * M[0][0] + Gi[3].g11 * M[0][1]
            // for col = 2:
            //   M[1][2] = Gi[3].g00 * M[0][2] + Gi[3].g01 * M[0][3]
            // for col = 3:
            //   M[1][3] = Gi[3].g10 * M[0][2] + Gi[3].g11 * M[0][3]
        }
        // The above loop is wrong for the odd columns. Rewrite row 1 explicitly
        // to match the C reference exactly.
        field.fp2Mul(tmp, Gi[3].g01, M.m[0][1]);
        field.fp2Mul(M.m[1][0], Gi[3].g00, M.m[0][0]);
        field.fp2Add(M.m[1][0], M.m[1][0], tmp);

        field.fp2Mul(tmp, Gi[3].g11, M.m[0][1]);
        field.fp2Mul(M.m[1][1], Gi[3].g10, M.m[0][0]);
        field.fp2Add(M.m[1][1], M.m[1][1], tmp);

        field.fp2Mul(tmp, Gi[3].g01, M.m[0][3]);
        field.fp2Mul(M.m[1][2], Gi[3].g00, M.m[0][2]);
        field.fp2Add(M.m[1][2], M.m[1][2], tmp);

        field.fp2Mul(tmp, Gi[3].g11, M.m[0][3]);
        field.fp2Mul(M.m[1][3], Gi[3].g10, M.m[0][2]);
        field.fp2Add(M.m[1][3], M.m[1][3], tmp);

        // Third row: action of (K1_4.P1, 0).
        field.fp2Mul(tmp, Gi[0].g01, M.m[0][2]);
        field.fp2Mul(M.m[2][0], Gi[0].g00, M.m[0][0]);
        field.fp2Add(M.m[2][0], M.m[2][0], tmp);

        field.fp2Mul(tmp, Gi[0].g01, M.m[0][3]);
        field.fp2Mul(M.m[2][1], Gi[0].g00, M.m[0][1]);
        field.fp2Add(M.m[2][1], M.m[2][1], tmp);

        field.fp2Mul(tmp, Gi[0].g11, M.m[0][2]);
        field.fp2Mul(M.m[2][2], Gi[0].g10, M.m[0][0]);
        field.fp2Add(M.m[2][2], M.m[2][2], tmp);

        field.fp2Mul(tmp, Gi[0].g11, M.m[0][3]);
        field.fp2Mul(M.m[2][3], Gi[0].g10, M.m[0][1]);
        field.fp2Add(M.m[2][3], M.m[2][3], tmp);

        // Fourth row: action of (K1_4.P1, K2_4.P2).
        field.fp2Mul(tmp, Gi[0].g01, M.m[1][2]);
        field.fp2Mul(M.m[3][0], Gi[0].g00, M.m[1][0]);
        field.fp2Add(M.m[3][0], M.m[3][0], tmp);

        field.fp2Mul(tmp, Gi[0].g01, M.m[1][3]);
        field.fp2Mul(M.m[3][1], Gi[0].g00, M.m[1][1]);
        field.fp2Add(M.m[3][1], M.m[3][1], tmp);

        field.fp2Mul(tmp, Gi[0].g11, M.m[1][2]);
        field.fp2Mul(M.m[3][2], Gi[0].g10, M.m[1][0]);
        field.fp2Add(M.m[3][2], M.m[3][2], tmp);

        field.fp2Mul(tmp, Gi[0].g11, M.m[1][3]);
        field.fp2Mul(M.m[3][3], Gi[0].g10, M.m[1][1]);
        field.fp2Add(M.m[3][3], M.m[3][3], tmp);
        return 1;
    }

    /**
     * {@code gluing_compute}: compute the gluing (2,2)-isogeny from
     * E1 × E2 with kernel [4](K1_8, K2_8). Returns 1 on success, 0 if the
     * kernel has the wrong order or the gluing is malformed.
     */
    public static int gluingCompute(GfField field, ThetaGluing out, ThetaCoupleCurve E12,
                                    ThetaCoupleJacPoint xyK1_8, ThetaCoupleJacPoint xyK2_8,
                                    boolean verify)
    {
        ThetaCoupleJacPoint.copy(out.xyK1_8, xyK1_8);
        // Copy E12 into out.domain.
        org.bouncycastle.pqc.crypto.sqisign.EcCurve.copy(out.domain.E1, E12.E1);
        org.bouncycastle.pqc.crypto.sqisign.EcCurve.copy(out.domain.E2, E12.E2);

        // [2] xyK1_8 and [2] xyK2_8 — the 4-torsion below the kernel.
        ThetaCoupleJacPoint xyK1_4 = new ThetaCoupleJacPoint();
        ThetaCoupleJacPoint xyK2_4 = new ThetaCoupleJacPoint();
        HdOps.doubleCoupleJacPoint(xyK1_4, xyK1_8, E12);
        HdOps.doubleCoupleJacPoint(xyK2_4, xyK2_8, E12);

        // Convert to (X : Z).
        ThetaCouplePoint K1_8 = new ThetaCouplePoint();
        ThetaCouplePoint K2_8 = new ThetaCouplePoint();
        ThetaCouplePoint K1_4 = new ThetaCouplePoint();
        ThetaCouplePoint K2_4 = new ThetaCouplePoint();
        HdOps.coupleJacToXz(field, K1_8, xyK1_8);
        HdOps.coupleJacToXz(field, K2_8, xyK2_8);
        HdOps.coupleJacToXz(field, K1_4, xyK1_4);
        HdOps.coupleJacToXz(field, K2_4, xyK2_4);

        if (gluingChangeOfBasis(field, out.M, K1_4, K2_4, E12) == 0)
        {
            return 0;
        }

        ThetaPoint TT1 = new ThetaPoint();
        ThetaPoint TT2 = new ThetaPoint();
        ThetaIsogenyOps.baseChange(field, TT1, out, K1_8);
        ThetaIsogenyOps.baseChange(field, TT2, out, K2_8);

        ThetaOps.toSquaredTheta(field, TT1, TT1);
        ThetaOps.toSquaredTheta(field, TT2, TT2);

        if ((Fp2.isZero(TT1.t) & Fp2.isZero(TT2.t)) == 0)
        {
            return 0;
        }
        if ((Fp2.isZero(TT1.x) | Fp2.isZero(TT2.x)
            | Fp2.isZero(TT1.y) | Fp2.isZero(TT2.z) | Fp2.isZero(TT1.z)) != 0)
        {
            return 0;
        }

        // Codomain: (Ax : Bx : Az : 0)
        field.fp2Mul(out.codomain.x, TT1.x, TT2.x);
        field.fp2Mul(out.codomain.y, TT1.y, TT2.x);
        field.fp2Mul(out.codomain.z, TT1.x, TT2.z);
        Fp2.setZero(out.codomain.t);
        // Precomputation vector for evaluation
        field.fp2Mul(out.precomputation.x, TT1.y, TT2.z);
        Fp2.copy(out.precomputation.y, out.codomain.z);
        Fp2.copy(out.precomputation.z, out.codomain.y);
        Fp2.setZero(out.precomputation.t);

        // imageK1_8 = (x : x : y : y) compact form
        field.fp2Mul(out.imageK1_8.x, TT1.x, out.precomputation.x);
        field.fp2Mul(out.imageK1_8.y, TT1.z, out.precomputation.z);

        if (verify)
        {
            Fp2 t1 = Fp2.zero(), t2 = Fp2.zero();
            field.fp2Mul(t1, TT1.y, out.precomputation.y);
            if (Fp2.isEqual(out.imageK1_8.x, t1) == 0)
            {
                return 0;
            }
            field.fp2Mul(t1, TT2.x, out.precomputation.x);
            field.fp2Mul(t2, TT2.z, out.precomputation.z);
            if (Fp2.isEqual(t2, t1) == 0)
            {
                return 0;
            }
        }

        ThetaOps.hadamard(field, out.codomain, out.codomain);
        return 1;
    }

    // ------------------------------------------------------------------
    // lvl1 convenience overloads
    // ------------------------------------------------------------------

    public static int gluingCompute(ThetaGluing out, ThetaCoupleCurve E12,
                                    ThetaCoupleJacPoint xyK1_8, ThetaCoupleJacPoint xyK2_8,
                                    boolean verify)
    {
        return gluingCompute(E12.E1.field, out, E12, xyK1_8, xyK2_8, verify);
    }
}
