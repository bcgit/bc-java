package org.bouncycastle.pqc.crypto.sphincs;

class Wots
{
    static final int  WOTS_LOGW = 4;

    static final int WOTS_W = (1 << WOTS_LOGW);
    static final int WOTS_L1 = ((256 + WOTS_LOGW - 1) / WOTS_LOGW);
    //#define WOTS_L 133  // for WOTS_W == 4
    //#define WOTS_L 90  // for WOTS_W == 8
    static final int WOTS_L = 67;  // for WOTS_W == 16
    static final int WOTS_LOG_L = 7; // for WOTS_W == 16
    static final int WOTS_SIGBYTES = (WOTS_L * SPHINCS256Config.HASH_BYTES);
    
    static void expand_seed(byte[] outseeds, int outOff, byte[] inseed, int inOff)
    {
        clear(outseeds, outOff, WOTS_L * SPHINCS256Config.HASH_BYTES);

        Seed.prg(outseeds, outOff, WOTS_L * SPHINCS256Config.HASH_BYTES, inseed, inOff);
    }

    private static void clear(byte[] bytes, int offSet, int length)
    {
        for (int i = 0; i != length; i++)
        {
            bytes[i + offSet] = 0;
        }
    }

    static void gen_chain(HashFunctions hs, byte[] out, int outOff, byte[] seed, int seedOff, byte[] masks, int masksOff, int chainlen)
    {
        int i, j;
        for (j = 0; j < SPHINCS256Config.HASH_BYTES; j++)
            out[j + outOff] = seed[j + seedOff];

        for (i = 0; i < chainlen && i < WOTS_W; i++)
            hs.hash_n_n_mask(out, outOff, out, outOff, masks, masksOff + (i * SPHINCS256Config.HASH_BYTES));
    }


    void wots_pkgen(HashFunctions hs, byte[] pk, int pkOff, byte[] sk, int skOff, byte[] masks, int masksOff)
    {
        int i;
        expand_seed(pk, pkOff, sk, skOff);
        for (i = 0; i < WOTS_L; i++)
            gen_chain(hs, pk, pkOff + i * SPHINCS256Config.HASH_BYTES, pk, pkOff + i * SPHINCS256Config.HASH_BYTES, masks, masksOff, WOTS_W - 1);
    }


    void wots_sign(HashFunctions hs, byte[] sig, int sigOff, byte[] msg, byte[] sk, byte[] masks)
    {
        int[] basew = new int[WOTS_L];
        int i, c = 0;

        for (i = 0; i < WOTS_L1; i += 2)
        {
            basew[i] = msg[i / 2] & 0xf;
            basew[i + 1] = (msg[i / 2] & 0xff) >>> 4;
            c += WOTS_W - 1 - basew[i];
            c += WOTS_W - 1 - basew[i + 1];
        }

        for (; i < WOTS_L; i++)
        {
            basew[i] = c & 0xf;
            c >>>= 4;
        }

        expand_seed(sig, sigOff, sk, 0);

        for (i = 0; i < WOTS_L; i++)
            gen_chain(hs, sig, sigOff + i * SPHINCS256Config.HASH_BYTES, sig, sigOff + i * SPHINCS256Config.HASH_BYTES, masks, 0, basew[i]);
    }

    void wots_verify(HashFunctions hs, byte[] pk, byte[] sig, int sigOff, byte[] msg, byte[] masks)
    {
        int[] basew = new int[WOTS_L];
        int i, c = 0;

        for (i = 0; i < WOTS_L1; i += 2)
        {
            basew[i] = msg[i / 2] & 0xf;
            basew[i + 1] = (msg[i / 2] & 0xff) >>> 4;
            c += WOTS_W - 1 - basew[i];
            c += WOTS_W - 1 - basew[i + 1];
        }

        for (; i < WOTS_L; i++)
        {
            basew[i] = c & 0xf;
            c >>>= 4;
        }

        for (i = 0; i < WOTS_L; i++)
            gen_chain(hs, pk, i * SPHINCS256Config.HASH_BYTES, sig, sigOff + i * SPHINCS256Config.HASH_BYTES, masks, (basew[i] * SPHINCS256Config.HASH_BYTES), WOTS_W - 1 - basew[i]);
    }
}
