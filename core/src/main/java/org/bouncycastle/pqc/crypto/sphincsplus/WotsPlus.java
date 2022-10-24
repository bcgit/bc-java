package org.bouncycastle.pqc.crypto.sphincsplus;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

class WotsPlus
{
    private final SPHINCSPlusEngine engine;
    private final int w;

    WotsPlus(SPHINCSPlusEngine engine)
    {
        this.engine = engine;
        this.w = this.engine.WOTS_W;
    }

    byte[] pkGen(byte[] skSeed, byte[] pkSeed, ADRS paramAdrs)
    {
        ADRS wotspkADRS = new ADRS(paramAdrs); // copy address to create OTS public key address

        byte[][] tmp = new byte[engine.WOTS_LEN][];
        for (int i = 0; i < engine.WOTS_LEN; i++)
        {
            ADRS adrs = new ADRS(paramAdrs);
            adrs.setType(ADRS.WOTS_PRF);
            adrs.setKeyPairAddress(paramAdrs.getKeyPairAddress());
            adrs.setChainAddress(i);
            adrs.setHashAddress(0);

            byte[] sk = engine.PRF(pkSeed, skSeed, adrs);

            adrs.setType(ADRS.WOTS_HASH);
            adrs.setKeyPairAddress(paramAdrs.getKeyPairAddress());
            adrs.setChainAddress(i);
            adrs.setHashAddress(0);
            tmp[i] = chain(sk, 0, w - 1, pkSeed, adrs);
        }

        wotspkADRS.setType(ADRS.WOTS_PK);
        wotspkADRS.setKeyPairAddress(paramAdrs.getKeyPairAddress());

        return engine.T_l(pkSeed, wotspkADRS, Arrays.concatenate(tmp));
    }

    // #Input: Input string X, start index i, number of steps s, public seed PK.seed, address ADRS
    // #Output: value of F iterated s times on X
    byte[] chain(byte[] X, int i, int s, byte[] pkSeed, ADRS adrs)
    {
        if (s == 0)
        {
            return Arrays.clone(X);
        }
        if ((i + s) > (this.w - 1))
        {
            return null;
        }
        byte[] result = X;
        for (int j = 0; j < s; ++j)
        {
            adrs.setHashAddress(i + j);
            result = engine.F(pkSeed, adrs, result);
        }
        return result;
    }

    // #Input: Message M, secret seed SK.seed, public seed PK.seed, address ADRS
    // #Output: WOTS+ signature sig
    public byte[] sign(byte[] M, byte[] skSeed, byte[] pkSeed, ADRS paramAdrs)
    {
        ADRS adrs = new ADRS(paramAdrs);

        int[] msg = new int[engine.WOTS_LEN];

        // convert message to base w
        base_w(M, 0, w, msg, 0, engine.WOTS_LEN1);

        // compute checksum
        int csum = 0;
        for (int i = 0; i < engine.WOTS_LEN1; i++)
        {
            csum += w - 1 - msg[i];
        }

        // convert csum to base w
        if ((engine.WOTS_LOGW % 8) != 0)
        {
            csum = csum << (8 - ((engine.WOTS_LEN2 * engine.WOTS_LOGW) % 8));
        }
        int len_2_bytes = (engine.WOTS_LEN2 * engine.WOTS_LOGW + 7) / 8;
        byte[] csum_bytes = Pack.intToBigEndian(csum);
        base_w(csum_bytes, 4 - len_2_bytes, w, msg, engine.WOTS_LEN1, engine.WOTS_LEN2);

        byte[][] sig = new byte[engine.WOTS_LEN][];
        for (int i = 0; i < engine.WOTS_LEN; i++)
        {
            adrs.setType(ADRS.WOTS_PRF);
            adrs.setKeyPairAddress(paramAdrs.getKeyPairAddress());
            adrs.setChainAddress(i);
            adrs.setHashAddress(0);
            byte[] sk = engine.PRF(pkSeed, skSeed, adrs);
            adrs.setType(ADRS.WOTS_HASH);
            adrs.setKeyPairAddress(paramAdrs.getKeyPairAddress());
            adrs.setChainAddress(i);
            adrs.setHashAddress(0);
            sig[i] = chain(sk, 0, msg[i], pkSeed, adrs);
        }
        return Arrays.concatenate(sig);
    }

    //
    // Input: len_X-byte string X, int w, output length out_len
    // Output: out_len int array basew
    void base_w(byte[] X, int XOff, int w, int[] output, int outOff, int outLen)
    {
        int total = 0;
        int bits = 0;

        for (int consumed = 0; consumed < outLen; consumed++)
        {
            if (bits == 0)
            {
                total = X[XOff++];
                bits += 8;
            }
            bits -= engine.WOTS_LOGW;
            output[outOff++] = ((total >>> bits) & (w - 1));
        }
    }

    public byte[] pkFromSig(byte[] sig, byte[] M, byte[] pkSeed, ADRS adrs)
    {
        ADRS wotspkADRS = new ADRS(adrs);

        int[] msg = new int[engine.WOTS_LEN];

        // convert message to base w
        base_w(M, 0, w, msg, 0, engine.WOTS_LEN1);

        // compute checksum
        int csum = 0;
        for (int i = 0; i < engine.WOTS_LEN1; i++ )
        {
            csum += w - 1 - msg[i];
        }

        // convert csum to base w
        csum = csum << (8 - ((engine.WOTS_LEN2 * engine.WOTS_LOGW) % 8));
        int len_2_bytes = (engine.WOTS_LEN2 * engine.WOTS_LOGW + 7) / 8;
        byte[] csum_bytes = Pack.intToBigEndian(csum);
        base_w(csum_bytes, 4 - len_2_bytes, w, msg, engine.WOTS_LEN1, engine.WOTS_LEN2);

        byte[] sigI = new byte[engine.N];
        byte[][] tmp = new byte[engine.WOTS_LEN][];
        for (int  i = 0; i < engine.WOTS_LEN; i++ )
        {
            adrs.setChainAddress(i);
            System.arraycopy(sig, i * engine.N, sigI, 0, engine.N);
            tmp[i] = chain(sigI, msg[i], w - 1 - msg[i], pkSeed, adrs);
        }

        wotspkADRS.setType(ADRS.WOTS_PK);
        wotspkADRS.setKeyPairAddress(adrs.getKeyPairAddress());
        
        return engine.T_l(pkSeed, wotspkADRS, Arrays.concatenate(tmp));
    }
}
