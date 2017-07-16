package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.modes.GCFBBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.ParametersWithSBox;
import org.bouncycastle.crypto.params.ParametersWithUKM;
import org.bouncycastle.util.Pack;

public class CryptoProWrapEngine
    extends GOST28147WrapEngine
{
    public void init(boolean forWrapping, CipherParameters param)
    {
        if (param instanceof ParametersWithRandom)
        {
            ParametersWithRandom pr = (ParametersWithRandom)param;
            param = pr.getParameters();
        }
        
        ParametersWithUKM pU = (ParametersWithUKM)param;
        byte[] sBox = null;


        KeyParameter kParam;

        if (pU.getParameters() instanceof ParametersWithSBox)
        {
            kParam = (KeyParameter)((ParametersWithSBox)pU.getParameters()).getParameters();
            sBox = ((ParametersWithSBox)pU.getParameters()).getSBox();
        }
        else
        {
            kParam = (KeyParameter)pU.getParameters();
        }

        kParam = new KeyParameter(cryptoProDiversify(kParam.getKey(), pU.getUKM(), sBox));

        if (sBox != null)
        {
            super.init(forWrapping, new ParametersWithUKM(new ParametersWithSBox(kParam, sBox), pU.getUKM()));
        }
        else
        {
            super.init(forWrapping, new ParametersWithUKM(kParam, pU.getUKM()));
        }
    }

    /*
         RFC 4357 6.5.  CryptoPro KEK Diversification Algorithm

         Given a random 64-bit UKM and a GOST 28147-89 key K, this algorithm
         creates a new GOST 28147-89 key K(UKM).

          1) Let K[0] = K;
          2) UKM is split into components a[i,j]:
             UKM = a[0]|..|a[7] (a[i] - byte, a[i,0]..a[i,7] - it's bits)
          3) Let i be 0.
          4) K[1]..K[8] are calculated by repeating the following algorithm
             eight times:
           A) K[i] is split into components k[i,j]:
              K[i] = k[i,0]|k[i,1]|..|k[i,7] (k[i,j] - 32-bit integer)
           B) Vector S[i] is calculated:
              S[i] = ((a[i,0]*k[i,0] + ... + a[i,7]*k[i,7]) mod 2^32) |
              (((~a[i,0])*k[i,0] + ... + (~a[i,7])*k[i,7]) mod 2^32);
           C) K[i+1] = encryptCFB (S[i], K[i], K[i])
           D) i = i + 1
          5) Let K(UKM) be K[8].
     */
    private static byte[] cryptoProDiversify(byte[] K, byte[] ukm, byte[] sBox)
    {
        for (int i = 0; i != 8; i++)
        {
            int sOn = 0;
            int sOff = 0;
            for (int j = 0; j != 8; j++)
            {
                int kj = Pack.littleEndianToInt(K, j * 4);
                if (bitSet(ukm[i], j))
                {
                    sOn += kj;
                }
                else
                {
                    sOff += kj;
                }
            }

            byte[] s = new byte[8];
            Pack.intToLittleEndian(sOn, s, 0);
            Pack.intToLittleEndian(sOff, s, 4);

            GCFBBlockCipher c = new GCFBBlockCipher(new GOST28147Engine());

            c.init(true, new ParametersWithIV(new ParametersWithSBox(new KeyParameter(K), sBox), s));

            c.processBlock(K, 0, K, 0);
            c.processBlock(K, 8, K, 8);
            c.processBlock(K, 16, K, 16);
            c.processBlock(K, 24, K, 24);
        }

        return K;
    }

    private static boolean bitSet(byte v, int bitNo)
    {
        return (v & (1 << bitNo)) != 0;
    }
}
