package org.bouncycastle.pqc.crypto.rainbow;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;

class RainbowDRBG
    extends SecureRandom
{
    private byte[] seed;
    private byte[] key;
    private byte[] v;
    private Digest hashAlgo;

    public RainbowDRBG(byte[] seed, Digest hashAlgo)
    {
        this.seed = seed;
        this.hashAlgo = hashAlgo;
        init(256);
    }


    private void init(int strength)
    {
        if (seed.length >= 48)
        {
            randombytes_init(seed, strength);
        }
        else
        {
            byte[] out = RainbowUtil.hash(hashAlgo, seed, 48 - seed.length);
            randombytes_init(Arrays.concatenate(seed, out), strength);
        }
    }

    @Override
    public void nextBytes(byte[] x)
    {
        byte[] block = new byte[16];
        int i = 0;

        int xlen = x.length;

        while (xlen > 0)
        {
            for (int j = 15; j >= 0; j--)
            {
                if ((v[j] & 0xFF) == 0xff)
                {
                    v[j] = 0x00;
                }
                else
                {
                    v[j]++;
                    break;
                }
            }

            AES256_ECB(key, v, block, 0);

            if (xlen > 15)
            {
                System.arraycopy(block, 0, x, i, block.length);
                i += 16;
                xlen -= 16;
            }
            else
            {
                System.arraycopy(block, 0, x, i, xlen);
                xlen = 0;
            }
        }

        AES256_CTR_DRBG_Update(null, key, v);
    }


    private void AES256_ECB(byte[] key, byte[] ctr, byte[] buffer, int startPosition)
    {
        try
        {
            AESEngine cipher = new AESEngine();

            cipher.init(true, new KeyParameter(key));

            for (int i = 0; i != ctr.length; i += 16)
            {
                cipher.processBlock(ctr, i, buffer, startPosition + i);
            }
        }
        catch (Throwable ex)
        {
            throw new IllegalStateException("drbg failure: " + ex.getMessage(), ex);
        }
    }


    private void AES256_CTR_DRBG_Update(byte[] entropy_input, byte[] key, byte[] v)
    {

        byte[] tmp = new byte[48];

        for (int i = 0; i < 3; i++)
        {
            //increment V
            for (int j = 15; j >= 0; j--)
            {
                if ((v[j] & 0xFF) == 0xff)
                {
                    v[j] = 0x00;
                }
                else
                {
                    v[j]++;
                    break;
                }
            }

            AES256_ECB(key, v, tmp, 16 * i);
        }

        if (entropy_input != null)
        {
            for (int i = 0; i < 48; i++)
            {
                tmp[i] ^= entropy_input[i];
            }
        }

        System.arraycopy(tmp, 0, key, 0, key.length);
        System.arraycopy(tmp, 32, v, 0, v.length);


    }


    private void randombytes_init(byte[] entropyInput, int strength)
    {
        byte[] seedMaterial = new byte[48];

        System.arraycopy(entropyInput, 0, seedMaterial, 0, seedMaterial.length);

        key = new byte[32];
        v = new byte[16];

        AES256_CTR_DRBG_Update(seedMaterial, key, v);
    }
}
