package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Evaluation of the gluing (2,2) theta isogeny on points outside the kernel.
 * Java port of {@code gluing_eval_point}, {@code gluing_eval_point_special_case},
 * and {@code gluing_eval_basis} from {@code theta_isogenies.c}.
 *
 * <p>Level-independent — uses only Fp²/EC Jacobian/HD ops we already have.</p>
 */
final class ThetaGluingEval
{
    private ThetaGluingEval()
    {
    }

    /**
     * {@code gluing_eval_point}: evaluate the gluing isogeny phi on a couple
     * of Jacobian points P. Uses the cross-addition components of (P, K1_8)
     * to construct the dual theta point of phi(P) before applying the
     * codomain precomputation and the Hadamard transform.
     */
    private static void gluingEvalPoint(GfField field, ThetaPoint image, ThetaCoupleJacPoint P, ThetaGluing phi)
    {
        AddComponents addComp1 = new AddComponents();
        AddComponents addComp2 = new AddComponents();
        EcJac.toXzAddComponents(addComp1, P.P1, phi.xyK1_8.P1, phi.domain.E1);
        EcJac.toXzAddComponents(addComp2, P.P2, phi.xyK1_8.P2, phi.domain.E2);

        ThetaPoint T1 = new ThetaPoint();
        ThetaPoint T2 = new ThetaPoint();

        field.fp2Mul(T1.x, addComp1.u, addComp2.u);
        field.fp2Mul(T2.t, addComp1.v, addComp2.v);
        field.fp2Add(T1.x, T1.x, T2.t);
        field.fp2Mul(T1.y, addComp1.u, addComp2.w);
        field.fp2Mul(T1.z, addComp1.w, addComp2.u);
        field.fp2Mul(T1.t, addComp1.w, addComp2.w);

        field.fp2Add(T2.x, addComp1.u, addComp1.v);
        field.fp2Add(T2.y, addComp2.u, addComp2.v);
        field.fp2Mul(T2.x, T2.x, T2.y);
        field.fp2Sub(T2.x, T2.x, T1.x);
        field.fp2Mul(T2.y, addComp1.v, addComp2.w);
        field.fp2Mul(T2.z, addComp1.w, addComp2.v);
        Fp2.setZero(T2.t);

        ThetaIsogenyOps.applyIsomorphismGeneral(field, T1, phi.M, T1, true);
        ThetaIsogenyOps.applyIsomorphismGeneral(field, T2, phi.M, T2, false);
        ThetaOps.pointwiseSquare(field, T1, T1);
        ThetaOps.pointwiseSquare(field, T2, T2);

        field.fp2Sub(T1.x, T1.x, T2.x);
        field.fp2Sub(T1.y, T1.y, T2.y);
        field.fp2Sub(T1.z, T1.z, T2.z);
        field.fp2Sub(T1.t, T1.t, T2.t);
        ThetaOps.hadamard(field, T1, T1);

        // imageK1_8 = (x : x : y : y); its "inverse" pattern is (y : y : x : x).
        field.fp2Mul(image.x, T1.x, phi.imageK1_8.y);
        field.fp2Mul(image.y, T1.y, phi.imageK1_8.y);
        field.fp2Mul(image.z, T1.z, phi.imageK1_8.x);
        field.fp2Mul(image.t, T1.t, phi.imageK1_8.x);

        ThetaOps.hadamard(field, image, image);
    }

    /**
     * {@code gluing_eval_point_special_case}: optimised evaluator when one of
     * the components of P is the zero point. Used by the chain driver for
     * pushing the input evaluation points (which are of the form (P1, ∞) or
     * (∞, P2)) through the gluing.
     *
     * @return 0 if the projective factor would force the t-coordinate to be
     * non-zero (a sign of a malformed input); 1 on success.
     */
    public static int gluingEvalPointSpecialCase(GfField field, ThetaPoint image, ThetaCouplePoint P, ThetaGluing phi)
    {
        ThetaPoint T = new ThetaPoint();
        ThetaIsogenyOps.baseChange(field, T, phi, P);
        ThetaOps.toSquaredTheta(field, T, T);

        if (Fp2.isZero(T.t) == 0)
        {
            return 0;
        }

        field.fp2Mul(image.x, T.x, phi.precomputation.x);
        field.fp2Mul(image.y, T.y, phi.precomputation.y);
        field.fp2Mul(image.z, T.z, phi.precomputation.z);
        Fp2.setZero(image.t);

        ThetaOps.hadamard(field, image, image);
        return 1;
    }

    /**
     * {@code gluing_eval_basis}: evaluate the gluing on two Jacobian couple
     * points simultaneously.
     */
    public static void gluingEvalBasis(GfField field, ThetaPoint image1, ThetaPoint image2,
                                       ThetaCoupleJacPoint xyT1, ThetaCoupleJacPoint xyT2,
                                       ThetaGluing phi)
    {
        gluingEvalPoint(field, image1, xyT1, phi);
        gluingEvalPoint(field, image2, xyT2, phi);
    }
}
