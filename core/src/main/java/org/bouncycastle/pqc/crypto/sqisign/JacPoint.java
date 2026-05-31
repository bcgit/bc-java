package org.bouncycastle.pqc.crypto.sqisign;


/** Jacobian point (X : Y : Z) on a Montgomery curve. */
final class JacPoint
{
    public final Fp2 x;
    public final Fp2 y;
    public final Fp2 z;

    public JacPoint()
    {
        this.x = Fp2.zero();
        this.y = Fp2.one();
        this.z = Fp2.zero();
    }

    public JacPoint(Fp2 x, Fp2 y, Fp2 z)
    {
        this.x = x.copy();
        this.y = y.copy();
        this.z = z.copy();
    }

    public JacPoint copy()
    {
        return new JacPoint(x, y, z);
    }

    public static void copy(JacPoint dst, JacPoint src)
    {
        Fp2.copy(dst.x, src.x);
        Fp2.copy(dst.y, src.y);
        Fp2.copy(dst.z, src.z);
    }
}
