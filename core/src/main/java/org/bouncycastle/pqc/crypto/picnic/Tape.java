package org.bouncycastle.pqc.crypto.picnic;

import org.bouncycastle.util.Pack;

class Tape
{
    byte[][] tapes;
    int pos;
    int nTapes;

    private PicnicEngine engine;
    public Tape(PicnicEngine engine)
    {
        this.engine = engine;
        tapes = new byte[engine.numMPCParties][2 * engine.andSizeBytes];
        pos = 0;
        nTapes = engine.numMPCParties;
    }

    protected void setAuxBits(byte[] input)
    {
        int last = engine.numMPCParties - 1;
        int pos = 0;
        int n = engine.stateSizeBits;

        for(int j = 0; j < engine.numRounds; j++)
        {
            for(int i = 0; i < n; i++)
            {
                Utils.setBit(this.tapes[last], n + n*2*j  + i, Utils.getBit(input, pos++));
            }
        }
    }

    /* Input is the tapes for one parallel repitition; i.e., tapes[t]
     * Updates the random tapes of all players with the mask values for the output of
     * AND gates, and computes the N-th party's share such that the AND gate invariant
     * holds on the mask values.
     */
    protected void computeAuxTape(byte[] inputs)
    {
        int[] roundKey = new int[PicnicEngine.LOWMC_MAX_WORDS];
        int[] x = new int[PicnicEngine.LOWMC_MAX_WORDS];
        int[] y = new int[PicnicEngine.LOWMC_MAX_WORDS];
        int[] key = new int[PicnicEngine.LOWMC_MAX_WORDS];
        int[] key0 = new int[PicnicEngine.LOWMC_MAX_WORDS];

        key0[engine.stateSizeWords - 1] = 0;
        tapesToParityBits(key0, engine.stateSizeBits);

//        System.out.print("key0: ");
//        for (int i = 0; i < key0.length; i++)
//        {System.out.printf("%08x ", key0[i]);}System.out.println();

        // key = key0 x KMatrix[0]^(-1)
        KMatricesWithPointer current = engine.lowmcConstants.KMatrixInv(engine);
        engine.matrix_mul(key, key0, current.getData(), current.getMatrixPointer());

//        System.out.print("key: ");
//        for (int i = 0; i < key0.length; i++)
//        {System.out.printf("%08x ", key[i]);}System.out.println();

        if (inputs != null)
        {
            Pack.intToLittleEndian(key, 0, engine.stateSizeWords, inputs, 0);
        }

        for (int r = engine.numRounds; r > 0; r--)
        {
            current = engine.lowmcConstants.KMatrix(engine, r);
            engine.matrix_mul(roundKey, key, current.getData(), current.getMatrixPointer());    // roundKey = key * KMatrix(r)

            engine.xor_array(x, x, roundKey, 0);

            current = engine.lowmcConstants.LMatrixInv(engine, r-1);
            engine.matrix_mul(y, x, current.getData(), current.getMatrixPointer());

            if(r == 1)
            {
                // Use key as input
                System.arraycopy(key0, 0, x, 0, key0.length);
            }
            else
            {
                this.pos = engine.stateSizeBits * 2 * (r - 1);
                // Read input mask shares from tapes
                tapesToParityBits(x, engine.stateSizeBits);
            }

            this.pos = engine.stateSizeBits * 2 * (r - 1) + engine.stateSizeBits;
            engine.aux_mpc_sbox(x, y, this);
        }

        // Reset the random tape counter so that the online execution uses the
        // same random bits as when computing the aux shares
        this.pos = 0;
    }

    private void tapesToParityBits(int[] output, int outputBitLen)
    {
        for (int i = 0; i < outputBitLen; i++)
        {
            Utils.setBitInWordArray(output, i, Utils.parity16(tapesToWord()));
        }
    }

    protected int tapesToWord()
    {
//        byte[] shares = new byte[4];
//
//        for (int i = 0; i < 16; i++)
//        {
//            byte bit = Utils.getBit(this.tapes[i], this.pos);
//            Utils.setBit(shares, i, bit);
//        }
//        this.pos++;
//        return Pack.littleEndianToInt(shares, 0);

        int shares = 0;
        int arrayPos = pos >>> 3, bitPos = (pos & 7) ^ 7;
        int bitMask = 1 << bitPos;

        shares |= (tapes[ 0][arrayPos] & bitMask) <<  7;
        shares |= (tapes[ 1][arrayPos] & bitMask) <<  6;
        shares |= (tapes[ 2][arrayPos] & bitMask) <<  5;
        shares |= (tapes[ 3][arrayPos] & bitMask) <<  4;
        shares |= (tapes[ 4][arrayPos] & bitMask) <<  3;
        shares |= (tapes[ 5][arrayPos] & bitMask) <<  2;
        shares |= (tapes[ 6][arrayPos] & bitMask) <<  1;
        shares |= (tapes[ 7][arrayPos] & bitMask) <<  0;

        shares |= (tapes[ 8][arrayPos] & bitMask) << 15;
        shares |= (tapes[ 9][arrayPos] & bitMask) << 14;
        shares |= (tapes[10][arrayPos] & bitMask) << 13;
        shares |= (tapes[11][arrayPos] & bitMask) << 12;
        shares |= (tapes[12][arrayPos] & bitMask) << 11;
        shares |= (tapes[13][arrayPos] & bitMask) << 10;
        shares |= (tapes[14][arrayPos] & bitMask) <<  9;
        shares |= (tapes[15][arrayPos] & bitMask) <<  8;

        this.pos++;
        return shares >>> bitPos;
    }
}
