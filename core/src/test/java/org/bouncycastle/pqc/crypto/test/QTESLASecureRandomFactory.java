package org.bouncycastle.pqc.crypto.test;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.test.FixedSecureRandom;

/**
 * Factory for producing FixedSecureRandom objects for use with testsing
 */
class QTESLASecureRandomFactory
{
    private byte[] seed;
    private byte[] personalization;
    private byte[] key;
    private byte[] v;
    int reseed_counuter = 1;


    /**
     * Return a seeded FixedSecureRandom representing the result of processing a
     * qTESLA test seed with the qTESLA RandomNumberGenerator.
     *
     * @param seed original qTESLA seed
     * @param strength bit-strength of the RNG required.
     * @return a FixedSecureRandom containing the correct amount of seed material for use with Java.
     */
    public static FixedSecureRandom getFixed(byte[] seed, int strength)
    {
        return getFixed(seed,null, strength, strength / 8, strength / 8);
    }

    public static FixedSecureRandom getFixed(byte[] seed, byte[] personalization, int strength, int discard, int size)
    {
        QTESLASecureRandomFactory teslaRNG = new QTESLASecureRandomFactory(seed, personalization);
        teslaRNG.init(strength);
        byte[] burn = new byte[discard];
        teslaRNG.nextBytes(burn);
        if (discard != size)
        {
            burn = new byte[size];
        }
        teslaRNG.nextBytes(burn);
        return new FixedSecureRandom(burn);
    }


    public static FixedSecureRandom getFixedNoDiscard(byte[] seed, int strength)
    {
        QTESLASecureRandomFactory teslaRNG = new QTESLASecureRandomFactory(seed, null);
        teslaRNG.init(strength);
        byte[] burn = new byte[strength / 8];
        teslaRNG.nextBytes(burn);
        return new FixedSecureRandom(burn);
    }

    private QTESLASecureRandomFactory(byte[] seed, byte[] personalization)
    {
        this.seed = seed;
        this.personalization = personalization;
    }


    private void init(int strength)
    {
        randombytes_init(seed, personalization, strength);
        reseed_counuter = 1;
    }

    private void nextBytes(byte[] x)
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
        reseed_counuter++;
    }


    private void AES256_ECB(byte[] key, byte[] ctr, byte[] buffer, int startPosition)
    {
        try
        {
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");

            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));

            cipher.doFinal(ctr, 0, ctr.length, buffer, startPosition);
        }
        catch (Throwable ex)
        {
            ex.printStackTrace();
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


    private void randombytes_init(byte[] entropyInput, byte[] personalization, int strength)
    {
        byte[] seedMaterial = new byte[48];

        System.arraycopy(entropyInput, 0, seedMaterial, 0, seedMaterial.length);
        if (personalization != null)
        {
            for (int i = 0; i < 48; i++)
            {
                seedMaterial[i] ^= personalization[i];
            }
        }

        key = new byte[32];
        v = new byte[16];


        AES256_CTR_DRBG_Update(seedMaterial, key, v);

        reseed_counuter = 1;

    }
}
