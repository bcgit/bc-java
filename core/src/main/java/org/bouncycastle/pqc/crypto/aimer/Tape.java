package org.bouncycastle.pqc.crypto.aimer;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.Pack;

/**
 * Tape structure for MPC party's state in AIMER
 */
class Tape
{
    final long[] ptShare;           // GF element (2 longs)
    final long[][] tShares;         // [AIMER_L][aim2NumWordsField] GF elements
    final long[] aShare;            // GF element (2 longs)
    final long[] cShare;  // GF element (2 longs)
    int aim2NumWordsField;

    public Tape(AIMerParameters params)
    {
        aim2NumWordsField = params.getAim2NumWordsField();
        this.ptShare = new long[aim2NumWordsField];
        this.tShares = new long[params.getAimerL()][aim2NumWordsField];
        this.aShare = new long[aim2NumWordsField];
        this.cShare = new long[aim2NumWordsField];
    }

    public void fromBytes(byte[] bytes, int offset)
    {
        int move = aim2NumWordsField << 3;
        Pack.littleEndianToLong(bytes, offset, ptShare);
        offset += move;

        // tShares
        for (int i = 0; i < tShares.length; i++)
        {
            Pack.littleEndianToLong(bytes, offset, tShares[i]);
            offset += move;
        }

        // aShare
        Pack.littleEndianToLong(bytes, offset, aShare);
        offset += move;

        // cShare
        Pack.littleEndianToLong(bytes, offset, cShare);
    }

    public void fromBytes(SHAKEDigest digest)
    {
        int bufSize = aim2NumWordsField << 3;
        byte[] buf = new byte[bufSize];
        digest.doOutput(buf, 0, bufSize);
        Pack.littleEndianToLong(buf, 0, ptShare);

        // tShares
        for (int i = 0; i < tShares.length; i++)
        {
            digest.doOutput(buf, 0, bufSize);
            Pack.littleEndianToLong(buf, 0, tShares[i]);
        }

        // aShare
        digest.doOutput(buf, 0, bufSize);
        Pack.littleEndianToLong(buf, 0, aShare);

        // cShare
        digest.doOutput(buf, 0, bufSize);
        Pack.littleEndianToLong(buf, 0, cShare);
    }
}
