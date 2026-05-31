package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Level-independent operations from {@code src/hd/ref/lvlx/theta_isogenies.c}:
 * theta-point coordinate selection, isomorphism application, basis-change
 * matrix multiplication, and the elliptic-product → theta-point base change.
 *
 * <p>The level-specific gluing / chain functions
 * ({@code gluing_compute}, {@code theta_isogeny_compute}, {@code theta_chain_compute_and_eval}, etc.)
 * depend on the precomp constant table {@code FP2_CONSTANTS} and the
 * precomputed {@code precomp_basis_change_matrix_t} entries; they land in a
 * separate lvl1-specific class once the precomp tables are regenerated.</p>
 */
final class ThetaIsogenyOps
{
    private ThetaIsogenyOps()
    {
    }

    /** {@code choose_index_theta_point}: select one of the four coordinates by mod-4 index. */
    public static void chooseIndexThetaPoint(Fp2 res, int ind, ThetaPoint T)
    {
        switch (ind % 4)
        {
            case 0: Fp2.copy(res, T.x); break;
            case 1: Fp2.copy(res, T.y); break;
            case 2: Fp2.copy(res, T.z); break;
            case 3: Fp2.copy(res, T.t); break;
        }
    }

    /**
     * {@code apply_isomorphism_general}: apply the 4×4 basis-change matrix M
     * to a theta point P. When {@code PtNotZero} is false, skip the column-3
     * contribution (saves four multiplications when P.t = 0).
     */
    public static void applyIsomorphismGeneral(GfField field, ThetaPoint res, BasisChangeMatrix M,
                                               ThetaPoint P, boolean PtNotZero)
    {
        Fp2 x1 = Fp2.zero();
        Fp2 tx = Fp2.zero(), ty = Fp2.zero();
        Fp2 tz = Fp2.zero(), tt = Fp2.zero();

        field.fp2Mul(tx, P.x, M.m[0][0]);
        field.fp2Mul(x1, P.y, M.m[0][1]);
        field.fp2Add(tx, tx, x1);
        field.fp2Mul(x1, P.z, M.m[0][2]);
        field.fp2Add(tx, tx, x1);

        field.fp2Mul(ty, P.x, M.m[1][0]);
        field.fp2Mul(x1, P.y, M.m[1][1]);
        field.fp2Add(ty, ty, x1);
        field.fp2Mul(x1, P.z, M.m[1][2]);
        field.fp2Add(ty, ty, x1);

        field.fp2Mul(tz, P.x, M.m[2][0]);
        field.fp2Mul(x1, P.y, M.m[2][1]);
        field.fp2Add(tz, tz, x1);
        field.fp2Mul(x1, P.z, M.m[2][2]);
        field.fp2Add(tz, tz, x1);

        field.fp2Mul(tt, P.x, M.m[3][0]);
        field.fp2Mul(x1, P.y, M.m[3][1]);
        field.fp2Add(tt, tt, x1);
        field.fp2Mul(x1, P.z, M.m[3][2]);
        field.fp2Add(tt, tt, x1);

        if (PtNotZero)
        {
            field.fp2Mul(x1, P.t, M.m[0][3]);
            field.fp2Add(tx, tx, x1);
            field.fp2Mul(x1, P.t, M.m[1][3]);
            field.fp2Add(ty, ty, x1);
            field.fp2Mul(x1, P.t, M.m[2][3]);
            field.fp2Add(tz, tz, x1);
            field.fp2Mul(x1, P.t, M.m[3][3]);
            field.fp2Add(tt, tt, x1);
        }

        Fp2.copy(res.x, tx);
        Fp2.copy(res.y, ty);
        Fp2.copy(res.z, tz);
        Fp2.copy(res.t, tt);
    }

    /** {@code apply_isomorphism}: full matrix application (P.t assumed nonzero). */
    public static void applyIsomorphism(GfField field, ThetaPoint res, BasisChangeMatrix M, ThetaPoint P)
    {
        applyIsomorphismGeneral(field, res, M, P, true);
    }

    /** {@code base_change_matrix_multiplication}: res ← M1 · M2. */
    public static void baseChangeMatrixMultiplication(GfField field, BasisChangeMatrix res,
                                                      BasisChangeMatrix M1,
                                                      BasisChangeMatrix M2)
    {
        BasisChangeMatrix tmp = new BasisChangeMatrix();
        Fp2 sum = Fp2.zero();
        Fp2 mik = Fp2.zero();
        Fp2 mkj = Fp2.zero();
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                Fp2.setZero(sum);
                for (int k = 0; k < 4; k++)
                {
                    Fp2.copy(mik, M1.m[i][k]);
                    Fp2.copy(mkj, M2.m[k][j]);
                    field.fp2Mul(mik, mik, mkj);
                    field.fp2Add(sum, sum, mik);
                }
                Fp2.copy(tmp.m[i][j], sum);
            }
        }
        BasisChangeMatrix.copy(res, tmp);
    }

    /**
     * {@code base_change}: build the theta point corresponding to an
     * elliptic-product couple-point T and apply the gluing's basis-change.
     *
     * <p>The null point (before basis change) is
     * (P1.x P2.x : P1.x P2.z : P2.x P1.z : P1.z P2.z).</p>
     */
    public static void baseChange(GfField field, ThetaPoint out, ThetaGluing phi, ThetaCouplePoint T)
    {
        ThetaPoint nullPoint = new ThetaPoint();
        field.fp2Mul(nullPoint.x, T.P1.x, T.P2.x);
        field.fp2Mul(nullPoint.y, T.P1.x, T.P2.z);
        field.fp2Mul(nullPoint.z, T.P2.x, T.P1.z);
        field.fp2Mul(nullPoint.t, T.P1.z, T.P2.z);
        applyIsomorphism(field, out, phi.M, nullPoint);
    }
}
