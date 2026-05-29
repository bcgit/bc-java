package org.bouncycastle.pqc.crypto.sqisign;


/** Theta point with four GF(p²) coordinates (x, y, z, t). */
final class ThetaPoint
{
    public final Fp2 x;
    public final Fp2 y;
    public final Fp2 z;
    public final Fp2 t;

    public ThetaPoint()
    {
        this.x = Fp2.zero();
        this.y = Fp2.zero();
        this.z = Fp2.zero();
        this.t = Fp2.zero();
    }
}
