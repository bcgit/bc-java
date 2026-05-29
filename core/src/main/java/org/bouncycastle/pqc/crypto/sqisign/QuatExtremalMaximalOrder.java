package org.bouncycastle.pqc.crypto.sqisign;

/**
 * The "extremal maximal order" data structure used by the SQIsign norm
 * equation solver: a maximal order O₀ in the quaternion algebra together
 * with two distinguished elements {@code z}, {@code t} satisfying
 * {@code z² = -q}, {@code t² = -p}. Mirrors C {@code quat_p_extremal_maximal_order_t}.
 */
final class QuatExtremalMaximalOrder
{
    /** The order itself, represented as a lattice. */
    public final QuatLattice order;
    /** Distinguished element with z² = -q. */
    public final QuatAlg.Elem z;
    /** Distinguished element with t² = -p, orthogonal to z. */
    public final QuatAlg.Elem t;
    /** |z²| = q. */
    public int q;

    public QuatExtremalMaximalOrder()
    {
        this.order = new QuatLattice();
        this.z = new QuatAlg.Elem();
        this.t = new QuatAlg.Elem();
        this.q = 1;
    }
}
