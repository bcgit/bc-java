package org.bouncycastle.pqc.crypto.sqisign;


/** Theta point with only two distinct coordinates (compact representation). */
final class ThetaPointCompact
{
    public final Fp2 x;
    public final Fp2 y;

    public ThetaPointCompact()
    {
        this.x = Fp2.zero();
        this.y = Fp2.zero();
    }
}
