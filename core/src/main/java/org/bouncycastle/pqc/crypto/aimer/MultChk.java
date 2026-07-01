package org.bouncycastle.pqc.crypto.aimer;

/**
 * Multi-check structure for MPC verification
 */
class MultChk
{
    final long[] ptShare;           // GF element (2 longs)
    final long[][] xShares;         // [AIMER_L + 1][2] GF elements
    final long[][] zShares;         // [AIMER_L + 1][2] GF elements

    public MultChk(AIMerParameters params)
    {
        int l = params.getAimerL();
        ptShare = new long[params.getAim2NumWordsField()];
        xShares = new long[l + 1][params.getAim2NumWordsField()];
        zShares = new long[l + 1][params.getAim2NumWordsField()];
    }
}
