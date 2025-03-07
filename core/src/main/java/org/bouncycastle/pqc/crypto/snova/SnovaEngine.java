package org.bouncycastle.pqc.crypto.snova;

public class SnovaEngine
{
    private final SnovaParameters params;
    private final int l;
    private final int lsq;
    final byte[][] S;
    final int[][] xS;

    public SnovaEngine(SnovaParameters params)
    {
        this.params = params;
        this.l = params.getL();
        this.lsq = l * l;
        S = new byte[l][lsq];
        xS = new int[l][lsq];
        be_aI(S[0], (byte)1);
        beTheS(S[1]);
        for (int index = 2; index < l; ++index)
        {
            GF16Utils.gf16mMul(S[index - 1], S[1], S[index], l);
        }

        for (int index = 0; index < l; ++index)
        {
            for (int ij = 0; ij < lsq; ++ij)
            {
                xS[index][ij]  = GF16Utils.gf16FromNibble(S[index][ij]);
            }
        }
    }

    public void be_aI(byte[] target, byte a)
    {
        // Mask 'a' to ensure it's a valid 4-bit GF16 element
        a = (byte)(a & 0x0F);

        for (int i = 0; i < l; ++i)
        {
            for (int j = 0; j < l; ++j)
            {
                int index = i * l + j;
                target[index] = (i == j) ? a : (byte)0;
            }
        }
    }

    private void beTheS(byte[] target)
    {
        // Set all elements to 8 - (i + j) in GF16 (4-bit values)
        for (int i = 0; i < l; ++i)
        {
            for (int j = 0; j < l; ++j)
            {
                int value = 8 - (i + j);
                target[i * l + j] = (byte)(value & 0x0F);  // Mask to 4 bits
            }
        }

        // Special case for rank 5
        if (l == 5)
        {
            target[4 * 5 + 4] = (byte)(9 & 0x0F);  // Set (4,4) to 9
        }
    }


}
