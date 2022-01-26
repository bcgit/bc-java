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
            adrs.setChainAddress(i);
            adrs.setHashAddress(0);
            byte[] sk = engine.PRF(pkSeed, skSeed, adrs);

            tmp[i] = chain(sk, 0, w - 1, pkSeed, adrs);
        }

        wotspkADRS.setType(ADRS.WOTS_PK);
        wotspkADRS.setKeyPairAddress(paramAdrs.getKeyPairAddress());

        return engine.T_l(pkSeed, wotspkADRS, Arrays.concatenate(tmp));
    }

    //    #Input: Input string X, start index i, number of steps s, public seed PK.seed,
//    address ADRS
//    #Output: value of F iterated s times on X
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
        byte[] tmp = chain(X, i, s - 1, pkSeed, adrs);
        adrs.setHashAddress(i + s - 1);
        tmp = engine.F(pkSeed, adrs, tmp);

        return tmp;
    }

    //
    // #Input: Message M, secret seed SK.seed, public seed PK.seed, address ADRS
    // #Output: WOTS+ signature sig
    public byte[] sign(byte[] M, byte[] skSeed, byte[] pkSeed, ADRS paramAdrs)
    {
        ADRS adrs = new ADRS(paramAdrs);

        int csum = 0;
        // convert message to base w
        int[] msg = base_w(M, w, engine.WOTS_LEN1);
        // compute checksum
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
        byte[] bytes = Pack.intToBigEndian(csum);
        msg = Arrays.concatenate(msg, base_w(Arrays.copyOfRange(bytes, len_2_bytes, bytes.length), w, engine.WOTS_LEN2));
        byte[][] sig = new byte[engine.WOTS_LEN][];
        for (int i = 0; i < engine.WOTS_LEN; i++)
        {
            adrs.setChainAddress(i);
            adrs.setHashAddress(0);
            byte[] sk = engine.PRF(pkSeed, skSeed, adrs);
            sig[i] = chain(sk, 0, msg[i], pkSeed, adrs);
        }
        return Arrays.concatenate(sig);
    }

    //
    // Input: len_X-byte string X, int w, output length out_len
    // Output: out_len int array basew
    int[] base_w(byte[] X, int w, int out_len)
    {
        int in = 0;
        int out = 0;
        int total = 0;
        int bits = 0;
        int[] output = new int[out_len];
        
        for (int consumed = 0; consumed < out_len; consumed++)
        {
            if (bits == 0)
            {
                total = X[in];
                in++;
                bits += 8;
            }
            bits -= engine.WOTS_LOGW;
            output[out] = ((total >>> bits) & (w - 1));
            out++;
        }
        return output;
    }

    public byte[] pkFromSig(byte[] sig, byte[] M, byte[] pkSeed, ADRS adrs)
    {
        int csum = 0;
        ADRS wotspkADRS = new ADRS(adrs);
        // convert message to base w
        int[] msg = base_w(M, w, engine.WOTS_LEN1);
        // compute checksum
        for (int i = 0; i < engine.WOTS_LEN1; i++ )
        {
            csum += w - 1 - msg[i];
        }
        // convert csum to base w
        csum = csum << (8 - ((engine.WOTS_LEN2 * engine.WOTS_LOGW) % 8));
        int len_2_bytes = (engine.WOTS_LEN2 * engine.WOTS_LOGW + 7) / 8;

        msg = Arrays.concatenate(msg, base_w(Arrays.copyOfRange(Pack.intToBigEndian(csum), 4 - len_2_bytes, 4), w, engine.WOTS_LEN2));

        byte[] sigI = new byte[engine.N];
        byte[][] tmp = new byte[engine.WOTS_LEN][];
        for (int  i = 0; i < engine.WOTS_LEN; i++ )
        {
            adrs.setChainAddress(i);
            System.arraycopy(sig, i * engine.N, sigI, 0, engine.N);
            tmp[i] = chain(sigI, msg[i], w - 1 - msg[i], pkSeed, adrs);
        }                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       // f6be78d057cc8056907ad2bf83cc8be7

        wotspkADRS.setType(ADRS.WOTS_PK);
        wotspkADRS.setKeyPairAddress(adrs.getKeyPairAddress());
        
        return engine.T_l(pkSeed, wotspkADRS, Arrays.concatenate(tmp));
    }
}
