package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Projective point (X : Z) on the Kummer line of a Montgomery curve.
 * Java port of {@code ec_point_t} from {@code src/ec/ref/include/ec.h}.
 * X-only representation; the y-coordinate is implicitly fixed up to sign.
 *
 * <p>Pure data type — the field operations live on {@code GfField}; this
 * class only allocates / copies / swaps cells, all of which are
 * level-independent.</p>
 */
final class EcPoint
{
    public final Fp2 x;
    public final Fp2 z;

    /** Constructs the point at infinity (1 : 0). */
    public EcPoint()
    {
        this.x = Fp2.one();
        this.z = Fp2.zero();
    }

    public EcPoint(Fp2 x, Fp2 z)
    {
        this.x = x.copy();
        this.z = z.copy();
    }

    public EcPoint copy()
    {
        return new EcPoint(x, z);
    }

    /** Mirrors the inline C {@code copy_point}. */
    public static void copy(EcPoint dst, EcPoint src)
    {
        Fp2.copy(dst.x, src.x);
        Fp2.copy(dst.z, src.z);
    }
}
