package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Differential-add components (u, v, w) such that
 * P + Q = (u - v : w) and P - Q = (u + v : w).
 * Mirrors C {@code add_components_t}.
 */
final class AddComponents
{
    public final Fp2 u;
    public final Fp2 v;
    public final Fp2 w;

    public AddComponents()
    {
        this.u = Fp2.zero();
        this.v = Fp2.zero();
        this.w = Fp2.zero();
    }
}
