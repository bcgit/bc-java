package org.bouncycastle.pqc.crypto.hawk;

class NTRUProfile
{
    public final int q;
    public final int minLogn;
    public final int maxLogn;
    public final int[] maxBlSmall;    // Length 11
    public final int[] maxBlLarge;    // Length 10
    public final int[] wordWin;       // Length 10
    public final int reduceBits;
    public final int[] coeffFGLimit;  // Length 11
    public final int[] minSaveFg;     // Length 11

    public NTRUProfile(int q, int minLogn, int maxLogn,
                       int[] maxBlSmall, int[] maxBlLarge, int[] wordWin,
                       int reduceBits, int[] coeffFGLimit, int[] minSaveFg)
    {
        this.q = q;
        this.minLogn = minLogn;
        this.maxLogn = maxLogn;
        this.maxBlSmall = (int[])maxBlSmall.clone();
        this.maxBlLarge = (int[])maxBlLarge.clone();
        this.wordWin = (int[])wordWin.clone();
        this.reduceBits = reduceBits;
        this.coeffFGLimit = (int[])coeffFGLimit.clone();
        this.minSaveFg = (int[])minSaveFg.clone();
    }

    // Validation method to ensure profile follows the rules
    public boolean validate()
    {
        if (maxBlSmall.length != 11 || maxBlLarge.length != 10 ||
            wordWin.length != 10 || coeffFGLimit.length != 11 ||
            minSaveFg.length != 11)
        {
            return false;
        }

        // Check: max_bl_small[0] = 1
        if (maxBlSmall[0] != 1)
        {
            return false;
        }

        // Check: max_bl_large[d] >= max_bl_small[d + 1] for d in [0,9]
        for (int d = 0; d < 10; d++)
        {
            if (maxBlLarge[d] < maxBlSmall[d + 1])
            {
                return false;
            }
        }

        // Check: 1 <= word_win[d] <= max_bl_small[d] for d in [0,9]
        for (int d = 0; d < 10; d++)
        {
            if (wordWin[d] < 1 || wordWin[d] > maxBlSmall[d])
            {
                return false;
            }
        }

        // Additional rules for optimized depth0 function:
        // max_bl_large[0] = 1
        if (maxBlLarge[0] != 1)
        {
            return false;
        }
        // max_bl_small[1] = 1
        if (maxBlSmall[1] != 1)
        {
            return false;
        }

        return true;
    }

    // Helper method to create a default profile (example values)
    public static NTRUProfile createDefault()
    {
        int[] maxBlSmall = {1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6};
        int[] maxBlLarge = {1, 2, 2, 3, 3, 4, 4, 5, 5, 6};
        int[] wordWin = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
        int[] coeffFGLimit = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        int[] minSaveFg = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

        return new NTRUProfile(12289, 1, 10, maxBlSmall, maxBlLarge,
            wordWin, 10, coeffFGLimit, minSaveFg);
    }
}