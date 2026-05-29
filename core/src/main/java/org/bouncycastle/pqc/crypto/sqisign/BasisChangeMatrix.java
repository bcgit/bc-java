package org.bouncycastle.pqc.crypto.sqisign;


/** 4×4 matrix over Fp² used for theta-point basis changes. */
final class BasisChangeMatrix
{
    public final Fp2[][] m;

    public BasisChangeMatrix()
    {
        this.m = new Fp2[4][4];
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                this.m[i][j] = Fp2.zero();
            }
        }
    }

    public static void copy(BasisChangeMatrix dst, BasisChangeMatrix src)
    {
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                Fp2.copy(dst.m[i][j], src.m[i][j]);
            }
        }
    }
}
