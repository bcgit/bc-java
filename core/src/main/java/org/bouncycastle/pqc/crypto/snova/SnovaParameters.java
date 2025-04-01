package org.bouncycastle.pqc.crypto.snova;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.GF16;

public class SnovaParameters
{
    static Map<Integer, byte[]> fixedAbqSet = new HashMap<Integer, byte[]>();//key is o
    static Map<Integer, byte[][]> sSet = new HashMap<Integer, byte[][]>(); //key is l
    static Map<Integer, int[][]> xSSet = new HashMap<Integer, int[][]>();

    public static final SnovaParameters SNOVA_24_5_16_4_SSK =
        new SnovaParameters("SNOVA_24_5_16_4_SSK", 24, 5, 4, true, false);
    public static final SnovaParameters SNOVA_24_5_16_4_ESK =
        new SnovaParameters("SNOVA_24_5_16_4_ESK", 24, 5, 4, false, false);
    public static final SnovaParameters SNOVA_24_5_16_4_SHAKE_SSK =
        new SnovaParameters("SNOVA_24_5_16_4_SHAKE_SSK", 24, 5, 4, true, true);
    public static final SnovaParameters SNOVA_24_5_16_4_SHAKE_ESK =
        new SnovaParameters("SNOVA_24_5_16_4_SHAKE_ESK", 24, 5, 4, false, true);

    public static final SnovaParameters SNOVA_24_5_16_5_SSK =
        new SnovaParameters("SNOVA_24_5_16_5_SSK", 24, 5, 5, true, false);
    public static final SnovaParameters SNOVA_24_5_16_5_ESK =
        new SnovaParameters("SNOVA_24_5_16_5_ESK", 24, 5, 5, false, false);
    public static final SnovaParameters SNOVA_24_5_16_5_SHAKE_SSK =
        new SnovaParameters("SNOVA_24_5_16_5_SHAKE_SSK", 24, 5, 5, true, true);
    public static final SnovaParameters SNOVA_24_5_16_5_SHAKE_ESK =
        new SnovaParameters("SNOVA_24_5_16_5_SHAKE_ESK", 24, 5, 5, false, true);

    public static final SnovaParameters SNOVA_25_8_16_3_SSK =
        new SnovaParameters("SNOVA_25_8_16_3_SSK", 25, 8, 3, true, false);
    public static final SnovaParameters SNOVA_25_8_16_3_ESK =
        new SnovaParameters("SNOVA_25_8_16_3_ESK", 25, 8, 3, false, false);
    public static final SnovaParameters SNOVA_25_8_16_3_SHAKE_SSK =
        new SnovaParameters("SNOVA_25_8_16_3_SHAKE_SSK", 25, 8, 3, true, true);
    public static final SnovaParameters SNOVA_25_8_16_3_SHAKE_ESK =
        new SnovaParameters("SNOVA_25_8_16_3_SHAKE_ESK", 25, 8, 3, false, true);

    public static final SnovaParameters SNOVA_29_6_16_5_SSK =
        new SnovaParameters("SNOVA_29_6_16_5_SSK", 29, 6, 5, true, false);
    public static final SnovaParameters SNOVA_29_6_16_5_ESK =
        new SnovaParameters("SNOVA_29_6_16_5_ESK", 29, 6, 5, false, false);
    public static final SnovaParameters SNOVA_29_6_16_5_SHAKE_SSK =
        new SnovaParameters("SNOVA_29_6_16_5_SHAKE_SSK", 29, 6, 5, true, true);
    public static final SnovaParameters SNOVA_29_6_16_5_SHAKE_ESK =
        new SnovaParameters("SNOVA_29_6_16_5_SHAKE_ESK", 29, 6, 5, false, true);

    public static final SnovaParameters SNOVA_37_8_16_4_SSK =
        new SnovaParameters("SNOVA_37_8_16_4_SSK", 37, 8, 4, true, false);
    public static final SnovaParameters SNOVA_37_8_16_4_ESK =
        new SnovaParameters("SNOVA_37_8_16_4_ESK", 37, 8, 4, false, false);
    public static final SnovaParameters SNOVA_37_8_16_4_SHAKE_SSK =
        new SnovaParameters("SNOVA_37_8_16_4_SHAKE_SSK", 37, 8, 4, true, true);
    public static final SnovaParameters SNOVA_37_8_16_4_SHAKE_ESK =
        new SnovaParameters("SNOVA_37_8_16_4_SHAKE_ESK", 37, 8, 4, false, true);

    // SNOVA_37_17_16_2 variants
    public static final SnovaParameters SNOVA_37_17_16_2_SSK =
        new SnovaParameters("SNOVA_37_17_16_2_SSK", 37, 17, 2, true, false);
    public static final SnovaParameters SNOVA_37_17_16_2_ESK =
        new SnovaParameters("SNOVA_37_17_16_2_ESK", 37, 17, 2, false, false);
    public static final SnovaParameters SNOVA_37_17_16_2_SHAKE_SSK =
        new SnovaParameters("SNOVA_37_17_16_2_SHAKE_SSK", 37, 17, 2, true, true);
    public static final SnovaParameters SNOVA_37_17_16_2_SHAKE_ESK =
        new SnovaParameters("SNOVA_37_17_16_2_SHAKE_ESK", 37, 17, 2, false, true);

    // SNOVA_49_11_16_3 variants
    public static final SnovaParameters SNOVA_49_11_16_3_SSK =
        new SnovaParameters("SNOVA_49_11_16_3_SSK", 49, 11, 3, true, false);
    public static final SnovaParameters SNOVA_49_11_16_3_ESK =
        new SnovaParameters("SNOVA_49_11_16_3_ESK", 49, 11, 3, false, false);
    public static final SnovaParameters SNOVA_49_11_16_3_SHAKE_SSK =
        new SnovaParameters("SNOVA_49_11_16_3_SHAKE_SSK", 49, 11, 3, true, true);
    public static final SnovaParameters SNOVA_49_11_16_3_SHAKE_ESK =
        new SnovaParameters("SNOVA_49_11_16_3_SHAKE_ESK", 49, 11, 3, false, true);

    // SNOVA_56_25_16_2 variants
    public static final SnovaParameters SNOVA_56_25_16_2_SSK =
        new SnovaParameters("SNOVA_56_25_16_2_SSK", 56, 25, 2, true, false);
    public static final SnovaParameters SNOVA_56_25_16_2_ESK =
        new SnovaParameters("SNOVA_56_25_16_2_ESK", 56, 25, 2, false, false);
    public static final SnovaParameters SNOVA_56_25_16_2_SHAKE_SSK =
        new SnovaParameters("SNOVA_56_25_16_2_SHAKE_SSK", 56, 25, 2, true, true);
    public static final SnovaParameters SNOVA_56_25_16_2_SHAKE_ESK =
        new SnovaParameters("SNOVA_56_25_16_2_SHAKE_ESK", 56, 25, 2, false, true);

    // SNOVA_60_10_16_4 variants
    public static final SnovaParameters SNOVA_60_10_16_4_SSK =
        new SnovaParameters("SNOVA_60_10_16_4_SSK", 60, 10, 4, true, false);
    public static final SnovaParameters SNOVA_60_10_16_4_ESK =
        new SnovaParameters("SNOVA_60_10_16_4_ESK", 60, 10, 4, false, false);
    public static final SnovaParameters SNOVA_60_10_16_4_SHAKE_SSK =
        new SnovaParameters("SNOVA_60_10_16_4_SHAKE_SSK", 60, 10, 4, true, true);
    public static final SnovaParameters SNOVA_60_10_16_4_SHAKE_ESK =
        new SnovaParameters("SNOVA_60_10_16_4_SHAKE_ESK", 60, 10, 4, false, true);

    // SNOVA_66_15_16_4 variants
    public static final SnovaParameters SNOVA_66_15_16_3_SSK =
        new SnovaParameters("SNOVA_66_15_16_3_SSK", 66, 15, 3, true, false);
    public static final SnovaParameters SNOVA_66_15_16_3_ESK =
        new SnovaParameters("SNOVA_66_15_16_3_ESK", 66, 15, 3, false, false);
    public static final SnovaParameters SNOVA_66_15_16_3_SHAKE_SSK =
        new SnovaParameters("SNOVA_66_15_16_3_SHAKE_SSK", 66, 15, 3, true, true);
    public static final SnovaParameters SNOVA_66_15_16_3_SHAKE_ESK =
        new SnovaParameters("SNOVA_66_15_16_3_SHAKE_ESK", 66, 15, 3, false, true);

    // SNOVA_75_33_16_2 variants
    public static final SnovaParameters SNOVA_75_33_16_2_SSK =
        new SnovaParameters("SNOVA_75_33_16_2_SSK", 75, 33, 2, true, false);
    public static final SnovaParameters SNOVA_75_33_16_2_ESK =
        new SnovaParameters("SNOVA_75_33_16_2_ESK", 75, 33, 2, false, false);
    public static final SnovaParameters SNOVA_75_33_16_2_SHAKE_SSK =
        new SnovaParameters("SNOVA_75_33_16_2_SHAKE_SSK", 75, 33, 2, true, true);
    public static final SnovaParameters SNOVA_75_33_16_2_SHAKE_ESK =
        new SnovaParameters("SNOVA_75_33_16_2_SHAKE_ESK", 75, 33, 2, false, true);

    private final String name;
    private final int v;
    private final int o;
    private final int l;
    private final int lsq;
    private final int alpha;
    private final boolean skIsSeed;
    private final boolean pkExpandShake;

    public SnovaParameters(String name, int v, int o, int l, boolean skIsSeed, boolean pkExpandShake)
    {
        this.name = name;
        this.v = v;
        this.o = o;
        this.l = l;
        this.lsq = l * l;
        this.alpha = lsq + l;
        this.skIsSeed = skIsSeed;
        this.pkExpandShake = pkExpandShake;
        if (!xSSet.containsKey(l))
        {
            byte[][] S = new byte[l][lsq];
            int[][] xS = new int[l][lsq];
            SnovaEngine.be_aI(S[0], 0, (byte)1, l);
            beTheS(S[1]);
            for (int index = 2; index < l; ++index)
            {
                GF16Utils.gf16mMul(S[index - 1], S[1], S[index], l);
            }

            for (int index = 0; index < l; ++index)
            {
                for (int ij = 0; ij < lsq; ++ij)
                {
                    xS[index][ij] = GF16Utils.gf16FromNibble(S[index][ij]);
                }
            }
            sSet.put(l, S);
            xSSet.put(l, xS);
        }
        if (l < 4 && !fixedAbqSet.containsKey(o))
        {
            SnovaEngine engine = new SnovaEngine(this);
            byte[] fixedAbq = new byte[4 * o * alpha * lsq];
            //genABQ(byte[] abqSeed)
            byte[] rngOut = new byte[o * alpha * (lsq + l)];
            byte[] q12 = new byte[2 * o * alpha * l];
            byte[] seed = "SNOVA_ABQ".getBytes();
            SHAKEDigest shake = new SHAKEDigest(256);
            shake.update(seed, 0, seed.length);
            shake.doFinal(rngOut, 0, rngOut.length);
            GF16.decode(rngOut, fixedAbq, 2 * o * alpha * lsq);
            GF16.decode(rngOut, alpha * lsq, q12, 0, 2 * o * alpha * l);
            // Post-processing for invertible matrices
            for (int pi = 0; pi < o; ++pi)
            {
                for (int a = 0; a < alpha; ++a)
                {
                    engine.makeInvertibleByAddingAS(fixedAbq, (pi * alpha + a) * lsq);
                    engine.makeInvertibleByAddingAS(fixedAbq, ((o + pi) * alpha + a) * lsq);
                    engine.genAFqS(q12, (pi * alpha + a) * l, fixedAbq, ((2 * o + pi) * alpha + a) * lsq);
                    engine.genAFqS(q12, ((o + pi) * alpha + a) * l, fixedAbq, ((3 * o + pi) * alpha + a) * lsq);
                }
            }
            fixedAbqSet.put(o, fixedAbq);
        }
    }

    // Getter methods
    public String getName()
    {
        return name;
    }

    public int getV()
    {
        return v;
    }

    public int getO()
    {
        return o;
    }

    public int getL()
    {
        return l;
    }

    public boolean isSkIsSeed()
    {
        return skIsSeed;
    }

    public boolean isPkExpandShake()
    {
        return pkExpandShake;
    }

    public int getM()
    {
        return o;
    }

    public int getAlpha()
    {
        return alpha;
    }

    public int getPublicKeyLength()
    {
        return SnovaKeyPairGenerator.publicSeedLength + ((o * o * o * l * l + 1) >>> 1);
    }

    public int getPrivateKeyLength()
    {
        return ((l * l * (4 * o * alpha + o * (v * v + v * o + o * v) + v * o) + 1) >> 1)
            + SnovaKeyPairGenerator.privateSeedLength + SnovaKeyPairGenerator.publicSeedLength;
    }

    public int getN()
    {
        return v + o;
    }

    public int getLsq()
    {
        return lsq;
    }

    public int getSaltLength()
    {
        return 16;
    }

    void beTheS(byte[] target)
    {
        // Set all elements to 8 - (i + j) in GF16 (4-bit values)
        for (int i = 0, il = 0; i < l; ++i, il += l)
        {
            for (int j = 0; j < l; ++j)
            {
                int value = 8 - (i + j);
                target[il + j] = (byte)(value & 0x0F);  // Mask to 4 bits
            }
        }

        // Special case for rank 5
        if (l == 5)
        {
            target[24] = (byte)9;  // Set (4,4) to 9
        }
    }
}
