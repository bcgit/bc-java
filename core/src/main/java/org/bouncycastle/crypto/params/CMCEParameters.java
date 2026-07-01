package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.KEMParameters;
import org.bouncycastle.crypto.kems.cmce.CMCEEngine;
import org.bouncycastle.util.Arrays;

/**
 * Parameter sets for the Classic McEliece KEM as standardised in ISO/IEC 18033-2:2006/Amd 2:2026,
 * Clause 13.
 * <p>
 * Four parameter sets are provided for each of the four standardised code sizes (460896, 6688128,
 * 6960119 and 8192128): a base set, a semi-systematic key-generation variant ("f"), a
 * plaintext-confirmation variant ("pc"), and a combined variant ("pcf"). All sixteen sets use
 * GF(2^13) and produce a 256-bit (32-byte) session key. The non-standardised mceliece348864 size is
 * not provided here; it remains available (deprecated) under {@code org.bouncycastle.pqc.crypto.cmce}.
 */
public class CMCEParameters
    implements KEMParameters
{
    private static final int[] poly4608 = new int[]{10, 9, 6, 0};
    private static final int[] poly6688 = new int[]{7, 2, 1, 0};
    private static final int[] poly6960 = new int[]{8, 0};
    private static final int[] poly8192 = new int[]{7, 2, 1, 0};

    public static final CMCEParameters mceliece460896 = new CMCEParameters("mceliece460896", 13, 4608, 96, poly4608, false, false, 256);
    public static final CMCEParameters mceliece460896f = new CMCEParameters("mceliece460896f", 13, 4608, 96, poly4608, true, false, 256);
    public static final CMCEParameters mceliece460896pc = new CMCEParameters("mceliece460896pc", 13, 4608, 96, poly4608, false, true, 256);
    public static final CMCEParameters mceliece460896pcf = new CMCEParameters("mceliece460896pcf", 13, 4608, 96, poly4608, true, true, 256);

    public static final CMCEParameters mceliece6688128 = new CMCEParameters("mceliece6688128", 13, 6688, 128, poly6688, false, false, 256);
    public static final CMCEParameters mceliece6688128f = new CMCEParameters("mceliece6688128f", 13, 6688, 128, poly6688, true, false, 256);
    public static final CMCEParameters mceliece6688128pc = new CMCEParameters("mceliece6688128pc", 13, 6688, 128, poly6688, false, true, 256);
    public static final CMCEParameters mceliece6688128pcf = new CMCEParameters("mceliece6688128pcf", 13, 6688, 128, poly6688, true, true, 256);

    public static final CMCEParameters mceliece6960119 = new CMCEParameters("mceliece6960119", 13, 6960, 119, poly6960, false, false, 256);
    public static final CMCEParameters mceliece6960119f = new CMCEParameters("mceliece6960119f", 13, 6960, 119, poly6960, true, false, 256);
    public static final CMCEParameters mceliece6960119pc = new CMCEParameters("mceliece6960119pc", 13, 6960, 119, poly6960, false, true, 256);
    public static final CMCEParameters mceliece6960119pcf = new CMCEParameters("mceliece6960119pcf", 13, 6960, 119, poly6960, true, true, 256);

    public static final CMCEParameters mceliece8192128 = new CMCEParameters("mceliece8192128", 13, 8192, 128, poly8192, false, false, 256);
    public static final CMCEParameters mceliece8192128f = new CMCEParameters("mceliece8192128f", 13, 8192, 128, poly8192, true, false, 256);
    public static final CMCEParameters mceliece8192128pc = new CMCEParameters("mceliece8192128pc", 13, 8192, 128, poly8192, false, true, 256);
    public static final CMCEParameters mceliece8192128pcf = new CMCEParameters("mceliece8192128pcf", 13, 8192, 128, poly8192, true, true, 256);

    private final String name;
    private final int m;
    private final int n;
    private final int t;
    private final int[] poly;
    private final boolean usePivots;
    private final boolean pc;
    private final int defaultKeySize;

    private CMCEParameters(String name, int m, int n, int t, int[] poly, boolean usePivots, boolean pc, int defaultKeySize)
    {
        this.name = name;
        this.m = m;
        this.n = n;
        this.t = t;
        this.poly = poly;
        this.usePivots = usePivots;
        this.pc = pc;
        this.defaultKeySize = defaultKeySize;
    }

    public String getName()
    {
        return name;
    }

    public int getM()
    {
        return m;
    }

    public int getN()
    {
        return n;
    }

    public int getT()
    {
        return t;
    }

    public int[] getPoly()
    {
        return Arrays.clone(poly);
    }

    public boolean isUsePivots()
    {
        return usePivots;
    }

    public boolean isPc()
    {
        return pc;
    }

    public int getSessionKeySize()
    {
        return defaultKeySize;
    }

    public int getEncapsulationLength()
    {
        return CMCEEngine.getInstance(this).getCipherTextSize();
    }
}
