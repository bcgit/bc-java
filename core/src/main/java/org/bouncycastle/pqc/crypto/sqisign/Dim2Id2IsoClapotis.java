package org.bouncycastle.pqc.crypto.sqisign;


import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Java port of {@code dim2id2iso_ideal_to_isogeny_clapotis} from
 * {@code src/id2iso/ref/lvlx/dim2id2iso.c} — the body of "keygen step 3":
 * given a left ideal {@code I} of the standard maximal order O₀, compute the
 * codomain curve {@code E_A} and the canonical 2^TORSION_EVEN_POWER-torsion
 * basis on it that is the image of the standard basis on E₀ under the secret
 * isogeny.
 *
 * <p>This is a long straight-line composition of the lower-level helpers
 * (find_uv → fixed_degree_isogeny ×2 → 2-power isogeny chain →
 * endomorphism-action correction). All of those helpers are ported; this
 * file wires them together. The {@code precomp} parameter bundle carries
 * the level-specific data (curves with endomorphisms, alternate connecting
 * ideals, etc.) the body needs to look up.</p>
 *
 * <p>The Java port is faithful to the C 1:1 modulo the dropped
 * {@code #ifndef NDEBUG} blocks (Weil-pairing-based assertions and order
 * checks). The single remaining Weil-pairing check picks the correct
 * codomain component out of the (2,2)-isogeny image — that one is part of
 * the production path, not a debug assertion.</p>
 */
final class Dim2Id2IsoClapotis
{
    private Dim2Id2IsoClapotis()
    {
    }

    /**
     * Precomp bundle that {@link #idealToIsogenyClapotis} consumes. Keeps
     * the level-specific data out of the function signature; build one for
     * each level you support.
     */
    public static final class Precomp
    {
        /** GF(p²) dispatch for this level (lvl1/3/5). */
        public final GfField field;
        /** {@code CURVES_WITH_ENDOMORPHISMS[i]} for {@code i ∈ 0..numAlternateOrders}. */
        public final CurveWithEndomorphismRing[] curvesWithEndomorphisms;
        /** {@code ALTERNATE_CONNECTING_IDEALS[i]} for {@code i ∈ 0..numAlternateOrders-1}. */
        public final QuatLeftIdeal[] alternateConnectingIdeals;
        /** {@code CONNECTING_IDEALS[i]} for {@code i ∈ 0..numAlternateOrders} — note 0-indexed, but only index >= 1 is dereferenced. */
        public final QuatLeftIdeal[] connectingIdeals;
        /** {@code quat_represent_integer_params} for each alternate order, indexed 0..numAlternateOrders. */
        public final QuatRepresentIntegerParams[] representIntegerParams;
        /** Number of alternate orders excluding the standard O₀ (lvl1: 6). */
        public final int numAlternateOrders;
        /** {@link PrecompLvl1#TORSION_EVEN_POWER}. */
        public final int torsionEvenPower;
        /** {@link PrecompLvl1#HD_EXTRA_TORSION}. */
        public final int hdExtraTorsion;
        /** {@link PrecompLvl1#QUAT_REPRES_BOUND_INPUT}. */
        public final int quatRepresBoundInput;
        /** {@link PrecompLvl1#FINDUV_BOX_SIZE}. */
        public final int finduvBoxSize;
        /** {@link PrecompLvl1#FINDUV_CUBE_SIZE}. */
        public final int finduvCubeSize;
        /** {@link PrecompLvl1#TORSION_PLUS_2POWER}. */
        public final Ibz torsionPlus2Power;

        /**
         * Full constructor. The {@code field} parameter carries the level
         * dispatch; lvl1 callers can use the 11-arg overload that defaults
         * to {@link GfFieldLvl1#INSTANCE}.
         */
        public Precomp(GfField field,
                       CurveWithEndomorphismRing[] curvesWithEndomorphisms,
                       QuatLeftIdeal[] alternateConnectingIdeals,
                       QuatLeftIdeal[] connectingIdeals,
                       QuatRepresentIntegerParams[] representIntegerParams,
                       int numAlternateOrders,
                       int torsionEvenPower, int hdExtraTorsion,
                       int quatRepresBoundInput,
                       int finduvBoxSize, int finduvCubeSize,
                       Ibz torsionPlus2Power)
        {
            this.field = field;
            this.curvesWithEndomorphisms = curvesWithEndomorphisms;
            this.alternateConnectingIdeals = alternateConnectingIdeals;
            this.connectingIdeals = connectingIdeals;
            this.representIntegerParams = representIntegerParams;
            this.numAlternateOrders = numAlternateOrders;
            this.torsionEvenPower = torsionEvenPower;
            this.hdExtraTorsion = hdExtraTorsion;
            this.quatRepresBoundInput = quatRepresBoundInput;
            this.finduvBoxSize = finduvBoxSize;
            this.finduvCubeSize = finduvCubeSize;
            this.torsionPlus2Power = torsionPlus2Power;
        }

        /** lvl1 convenience constructor: defaults {@code field} to {@code GfFieldLvl1.INSTANCE}. */
        public Precomp(CurveWithEndomorphismRing[] curvesWithEndomorphisms,
                       QuatLeftIdeal[] alternateConnectingIdeals,
                       QuatLeftIdeal[] connectingIdeals,
                       QuatRepresentIntegerParams[] representIntegerParams,
                       int numAlternateOrders,
                       int torsionEvenPower, int hdExtraTorsion,
                       int quatRepresBoundInput,
                       int finduvBoxSize, int finduvCubeSize,
                       Ibz torsionPlus2Power)
        {
            this(GfFieldLvl1.INSTANCE,
                 curvesWithEndomorphisms, alternateConnectingIdeals, connectingIdeals,
                 representIntegerParams, numAlternateOrders, torsionEvenPower,
                 hdExtraTorsion, quatRepresBoundInput, finduvBoxSize, finduvCubeSize,
                 torsionPlus2Power);
        }
    }

    /** Bundled outputs: mirrors the C signature's eight output-by-pointer parameters. */
    public static final class Result
    {
        public final QuatAlg.Elem beta1 = new QuatAlg.Elem();
        public final QuatAlg.Elem beta2 = new QuatAlg.Elem();
        public final Ibz u = new Ibz();
        public final Ibz v = new Ibz();
        public final Ibz d1 = new Ibz();
        public final Ibz d2 = new Ibz();
        public final EcCurve codomain = new EcCurve();
        public final EcBasis basis = new EcBasis();
    }

    /**
     * {@code dim2id2iso_ideal_to_isogeny_clapotis}.
     *
     * @return a populated {@link Result} on success, or {@code null} if any
     *         step (find_uv, fixed_degree_isogeny ×2, or the (2,2)-chain)
     *         rejected.
     */
    public static Result idealToIsogenyClapotis(QuatLeftIdeal lideal, QuatAlg alg,
                                                Precomp precomp, SecureRandom random)
    {
        // Dispatch GF(p²) ops through the level the precomp was built for.
        final GfField field = precomp.field;

        // Step 1: find_uv across the standard order and all alternate orders.
        Dim2Id2IsoHelpers.FindUvResult fuv = Dim2Id2IsoHelpers.findUv(
            precomp.torsionPlus2Power, lideal, alg,
            precomp.numAlternateOrders, precomp.alternateConnectingIdeals,
            precomp.finduvBoxSize, precomp.finduvCubeSize);
        if (fuv == null)
        {
            return null;
        }
        int indexOrder1 = fuv.indexAlternateOrder1;
        int indexOrder2 = fuv.indexAlternateOrder2;

        if (!fuv.d1.v.testBit(0) || !fuv.d2.v.testBit(0))
        {
            // The C reference asserts d1 and d2 are odd.
            return null;
        }

        // Step 2: strip the common 2-adic valuation from (u, v).
        BigInteger uv = fuv.u.v.gcd(fuv.v.v);
        if (uv.signum() == 0)
        {
            return null;
        }
        int expGcd = uv.getLowestSetBit();
        int exp = precomp.torsionEvenPower - expGcd;
        BigInteger gcd2Pow = BigInteger.ONE.shiftLeft(expGcd);
        if (fuv.u.v.mod(gcd2Pow).signum() != 0 || fuv.v.v.mod(gcd2Pow).signum() != 0)
        {
            return null;
        }
        fuv.u.v = fuv.u.v.shiftRight(expGcd);
        fuv.v.v = fuv.v.v.shiftRight(expGcd);

        // Step 3: theta = beta2 · conj(beta1) / lideal.norm.
        QuatAlg.Elem theta = new QuatAlg.Elem();
        Ibz.set(theta.denom, 1);
        QuatAlg.conj(theta, fuv.beta1);
        QuatAlg.mul(theta, fuv.beta2, theta, alg);
        Ibz.mul(theta.denom, theta.denom, lideal.norm);

        // Step 4: build per-order curve & basis copies.
        CurveWithEndomorphismRing c1 = precomp.curvesWithEndomorphisms[indexOrder1];
        CurveWithEndomorphismRing c2 = precomp.curvesWithEndomorphisms[indexOrder2];
        EcCurve E1 = new EcCurve();
        EcCurve E2 = new EcCurve();
        EcCurve.copy(E1, c1.curve);
        EcCurve.copy(E2, c2.curve);
        EcBasis bas1 = new EcBasis();
        EcBasis bas2 = new EcBasis();
        EcBasis.copy(bas1, c1.basisEven);
        EcBasis.copy(bas2, c2.basisEven);

        // Step 5: fixed_degree_isogeny on (E1, bas1) with degree u.
        QuatLeftIdeal idealU = new QuatLeftIdeal();
        ThetaCoupleCurve fuCodomain = new ThetaCoupleCurve();
        ThetaCouplePoint[] pushed = new ThetaCouplePoint[3];
        for (int i = 0; i < 3; i++)
        {
            pushed[i] = new ThetaCouplePoint();
        }
        // Initialise pushed_points from bas1 (P1 = basis pts, P2 = identity).
        EcPoint.copy(pushed[0].P1, bas1.P);   EcOps.pointInit(pushed[0].P2);
        EcPoint.copy(pushed[1].P1, bas1.Q);   EcOps.pointInit(pushed[1].P2);
        EcPoint.copy(pushed[2].P1, bas1.PmQ); EcOps.pointInit(pushed[2].P2);

        int retU = Dim2Id2IsoHelpers.fixedDegreeIsogenyImpl(
            idealU, fuv.u, true, fuCodomain, pushed, 3,
            c1.curve, c1.basisEven, precomp.representIntegerParams[indexOrder1],
            c1.actionGen2, c1.actionGen3, c1.actionGen4, alg,
            precomp.torsionEvenPower, precomp.hdExtraTorsion,
            precomp.quatRepresBoundInput, random);
        if (retU == 0)
        {
            return null;
        }

        // basU = images of (P, Q, PmQ) on fuCodomain.E1.
        EcBasis basU = new EcBasis();
        EcPoint.copy(basU.P,   pushed[0].P1);
        EcPoint.copy(basU.Q,   pushed[1].P1);
        EcPoint.copy(basU.PmQ, pushed[2].P1);

        // Step 6: kernel point T_*.P1 := basU, curve E01.E1 := fuCodomain.E1.
        ThetaKernelCouplePoints ker = new ThetaKernelCouplePoints();
        EcPoint.copy(ker.T1.P1,   basU.P);
        EcPoint.copy(ker.T2.P1,   basU.Q);
        EcPoint.copy(ker.T1m2.P1, basU.PmQ);
        ThetaCoupleCurve E01 = new ThetaCoupleCurve();
        EcCurve.copy(E01.E1, fuCodomain.E1);

        // Step 7: fixed_degree_isogeny on (E2, bas2) with degree v.
        EcPoint.copy(pushed[0].P1, bas2.P);   EcOps.pointInit(pushed[0].P2);
        EcPoint.copy(pushed[1].P1, bas2.Q);   EcOps.pointInit(pushed[1].P2);
        EcPoint.copy(pushed[2].P1, bas2.PmQ); EcOps.pointInit(pushed[2].P2);

        QuatLeftIdeal idealV = new QuatLeftIdeal();
        ThetaCoupleCurve fvCodomain = new ThetaCoupleCurve();
        int retV = Dim2Id2IsoHelpers.fixedDegreeIsogenyImpl(
            idealV, fuv.v, true, fvCodomain, pushed, 3,
            c2.curve, c2.basisEven, precomp.representIntegerParams[indexOrder2],
            c2.actionGen2, c2.actionGen3, c2.actionGen4, alg,
            precomp.torsionEvenPower, precomp.hdExtraTorsion,
            precomp.quatRepresBoundInput, random);
        if (retV == 0)
        {
            return null;
        }

        EcPoint.copy(bas2.P,   pushed[0].P1);
        EcPoint.copy(bas2.Q,   pushed[1].P1);
        EcPoint.copy(bas2.PmQ, pushed[2].P1);

        // Step 8: scale theta by 1 / (d1 · n(ACI[index_order2-1])) mod 2^TORSION_EVEN_POWER.
        BigInteger mod2T = BigInteger.ONE.shiftLeft(precomp.torsionEvenPower);
        BigInteger scaleDen = fuv.d1.v;
        if (indexOrder2 > 0)
        {
            scaleDen = scaleDen.multiply(precomp.alternateConnectingIdeals[indexOrder2 - 1].norm.v);
        }
        BigInteger scale;
        try
        {
            scale = scaleDen.modInverse(mod2T);
        }
        catch (ArithmeticException e)
        {
            return null;
        }
        Ibz scaleIbz = new Ibz(scale);
        for (int i = 0; i < 4; i++)
        {
            Ibz.mul(theta.coord[i], theta.coord[i], scaleIbz);
        }

        // Step 9: apply theta to bas2 on fvCodomain.E1.
        CurveWithEndomorphismRing c0 = precomp.curvesWithEndomorphisms[0];
        int applied = Id2IsoHelpers.endomorphismApplicationEvenBasis(
            bas2, fvCodomain.E1, theta, precomp.torsionEvenPower,
            precomp.representIntegerParams[0].order.order,
            c0.actionGen2, c0.actionGen3, c0.actionGen4);
        if (applied != 1)
        {
            return null;
        }

        // Step 10: kernel T_*.P2 := bas2; E01.E2 := fvCodomain.E1.
        EcPoint.copy(ker.T1.P2,   bas2.P);
        EcPoint.copy(ker.T2.P2,   bas2.Q);
        EcPoint.copy(ker.T1m2.P2, bas2.PmQ);
        EcCurve.copy(E01.E2, fvCodomain.E1);

        // Step 11: double ker down by (TORSION_EVEN_POWER - exp) iterations.
        int dblIters = precomp.torsionEvenPower - exp;
        if (dblIters > 0)
        {
            HdOps.doubleCouplePointIter(ker.T1,   dblIters, ker.T1,   E01);
            HdOps.doubleCouplePointIter(ker.T2,   dblIters, ker.T2,   E01);
            HdOps.doubleCouplePointIter(ker.T1m2, dblIters, ker.T1m2, E01);
        }

        if (!fuv.u.v.testBit(0))
        {
            // C reference asserts ibz_is_odd(u).
            return null;
        }

        // Step 12: pushed_points := (basU, identity) ready for the chain.
        EcPoint.copy(pushed[0].P1, basU.P);   EcOps.pointInit(pushed[0].P2);
        EcPoint.copy(pushed[1].P1, basU.Q);   EcOps.pointInit(pushed[1].P2);
        EcPoint.copy(pushed[2].P1, basU.PmQ); EcOps.pointInit(pushed[2].P2);

        // Step 13: run the (2,2)-isogeny chain (randomized variant).
        // Dispatch to the level-specific chain implementation.
        ThetaCoupleCurve thetaCodomain = new ThetaCoupleCurve();
        int chainRet;
        if (field == GfFieldLvl3.INSTANCE)
        {
            chainRet = ThetaChainLvl3.chainComputeAndEvalRandomized(
                exp, E01, ker, false, thetaCodomain, pushed, 3, random);
        }
        else if (field == GfFieldLvl5.INSTANCE)
        {
            chainRet = ThetaChainLvl5.chainComputeAndEvalRandomized(
                exp, E01, ker, false, thetaCodomain, pushed, 3, random);
        }
        else
        {
            chainRet = ThetaChainLvl1.chainComputeAndEvalRandomized(
                exp, E01, ker, false, thetaCodomain, pushed, 3, random);
        }
        if (chainRet == 0)
        {
            return null;
        }

        // Step 14: select the codomain component via Weil pairing.
        Result result = new Result();
        EcPoint.copy(result.basis.P,   pushed[0].P1);
        EcPoint.copy(result.basis.Q,   pushed[1].P1);
        EcPoint.copy(result.basis.PmQ, pushed[2].P1);
        EcCurve.copy(result.codomain,  thetaCodomain.E1);

        Fp2 w0 = Fp2.zero(), w1 = Fp2.zero();
        EcBiext.weil(field, w0, precomp.torsionEvenPower, bas1.P, bas1.Q, bas1.PmQ, E1);
        EcBiext.weil(field, w1, precomp.torsionEvenPower, result.basis.P, result.basis.Q,
            result.basis.PmQ, result.codomain);

        BigInteger d1uu = fuv.d1.v.multiply(fuv.u.v).multiply(fuv.u.v).mod(mod2T);
        Fp2 testPow = Fp2.zero();
        field.fp2PowVartime(testPow, w0, d1uu);
        if (Fp2.isEqual(w1, testPow) == 0)
        {
            EcPoint.copy(result.basis.P,   pushed[0].P2);
            EcPoint.copy(result.basis.Q,   pushed[1].P2);
            EcPoint.copy(result.basis.PmQ, pushed[2].P2);
            EcCurve.copy(result.codomain,  thetaCodomain.E2);
        }

        // Step 15: scale beta1 by (u · d1 · n(CONNECTING_IDEALS[index_order1]))^{-1} mod 2^TORSION_EVEN_POWER.
        BigInteger beta1Scale = fuv.u.v.multiply(fuv.d1.v);
        if (indexOrder1 != 0)
        {
            beta1Scale = beta1Scale.multiply(precomp.connectingIdeals[indexOrder1].norm.v);
        }
        BigInteger beta1ScaleInv;
        try
        {
            beta1ScaleInv = beta1Scale.modInverse(mod2T);
        }
        catch (ArithmeticException e)
        {
            return null;
        }
        Ibz beta1ScaleInvIbz = new Ibz(beta1ScaleInv);
        for (int i = 0; i < 4; i++)
        {
            Ibz.mul(fuv.beta1.coord[i], fuv.beta1.coord[i], beta1ScaleInvIbz);
        }

        // Step 16: apply beta1 to the basis on codomain (using order index 0).
        int appliedBeta1 = Id2IsoHelpers.endomorphismApplicationEvenBasis(
            result.basis, result.codomain, fuv.beta1, precomp.torsionEvenPower,
            precomp.representIntegerParams[0].order.order,
            c0.actionGen2, c0.actionGen3, c0.actionGen4);
        if (appliedBeta1 != 1)
        {
            return null;
        }

        // Fill the rest of the Result.
        QuatAlg.copyElem(result.beta1, fuv.beta1);
        QuatAlg.copyElem(result.beta2, fuv.beta2);
        Ibz.copy(result.u, fuv.u);
        Ibz.copy(result.v, fuv.v);
        Ibz.copy(result.d1, fuv.d1);
        Ibz.copy(result.d2, fuv.d2);
        return result;
    }
}
