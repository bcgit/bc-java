package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Java mirror of the C struct {@code curve_with_endomorphism_ring_t} from
 * {@code src/precomp/ref/lvl1/include/endomorphism_action.h}.
 *
 * <p>Holds a Montgomery curve, a precomputed (deterministic) even-torsion
 * basis on that curve, and six 2×2 integer matrices encoding the action of
 * the endomorphism ring on that basis: {@code action_i}, {@code action_j},
 * {@code action_k} (i, j, k = ij of the quaternion algebra) and
 * {@code action_gen2}, {@code action_gen3}, {@code action_gen4} (the
 * generators of the maximal order O₀).</p>
 *
 * <p>The published table {@code CURVES_WITH_ENDOMORPHISMS[7]} contains the
 * primary curve E₀ at index 0 plus six alternate starting curves; all seven
 * entries are populated, translated from the constants in
 * {@code precomp/ref/lvl1/endomorphism_action.c}.</p>
 */
final class CurveWithEndomorphismRing
{
    public final EcCurve curve;
    public final EcBasis basisEven;
    public final Ibz[][] actionI;
    public final Ibz[][] actionJ;
    public final Ibz[][] actionK;
    public final Ibz[][] actionGen2;
    public final Ibz[][] actionGen3;
    public final Ibz[][] actionGen4;

    public CurveWithEndomorphismRing()
    {
        this.curve = new EcCurve();
        this.basisEven = new EcBasis();
        this.actionI = new Ibz[2][2];
        this.actionJ = new Ibz[2][2];
        this.actionK = new Ibz[2][2];
        this.actionGen2 = new Ibz[2][2];
        this.actionGen3 = new Ibz[2][2];
        this.actionGen4 = new Ibz[2][2];
        for (int i = 0; i < 2; i++)
        {
            for (int j = 0; j < 2; j++)
            {
                this.actionI[i][j] = new Ibz();
                this.actionJ[i][j] = new Ibz();
                this.actionK[i][j] = new Ibz();
                this.actionGen2[i][j] = new Ibz();
                this.actionGen3[i][j] = new Ibz();
                this.actionGen4[i][j] = new Ibz();
            }
        }
    }
}
