package org.bouncycastle.pqc.crypto.cmce;

import org.bouncycastle.pqc.crypto.KEMParameters;

public class CMCEParameters
    implements KEMParameters
{
    private static int[] poly3488 = new int[]{3, 1, 0};
    private static int[] poly4608 = new int[]{10, 9, 6, 0};
    private static int[] poly6688 = new int[]{7, 2, 1, 0};
    private static int[] poly6960 = new int[]{8, 0};
    private static int[] poly8192 = new int[]{7, 2, 1, 0};

    public static final CMCEParameters mceliece348864r3 = new CMCEParameters("mceliece348864", 12, 3488, 64, poly3488, false, 128);
    public static final CMCEParameters mceliece348864fr3 = new CMCEParameters("mceliece348864f", 12, 3488, 64, poly3488, true, 128);
    public static final CMCEParameters mceliece460896r3 = new CMCEParameters("mceliece460896", 13, 4608, 96, poly4608, false, 192);
    public static final CMCEParameters mceliece460896fr3 = new CMCEParameters("mceliece460896f", 13, 4608, 96, poly4608, true, 192);
    public static final CMCEParameters mceliece6688128r3 = new CMCEParameters("mceliece6688128", 13, 6688, 128, poly6688, false, 256);
    public static final CMCEParameters mceliece6688128fr3 = new CMCEParameters("mceliece6688128f", 13, 6688, 128, poly6688, true, 256);
    public static final CMCEParameters mceliece6960119r3 = new CMCEParameters("mceliece6960119", 13, 6960, 119, poly6960, false, 256);
    public static final CMCEParameters mceliece6960119fr3 = new CMCEParameters("mceliece6960119f", 13, 6960, 119, poly6960, true, 256);
    public static final CMCEParameters mceliece8192128r3 = new CMCEParameters("mceliece8192128", 13, 8192, 128, poly8192, false, 256);
    public static final CMCEParameters mceliece8192128fr3 = new CMCEParameters("mceliece8192128f", 13, 8192, 128, poly8192, true, 256);
    
    private final String name;
    private final int m;
    private final int n;
    private final int t;
    private final boolean usePivots;
    private final int defaultKeySize;
    private final CMCEEngine engine;

    private CMCEParameters(String name, int m, int n, int t, int[] p, boolean usePivots, int defaultKeySize)
    {
        this.name = name;
        this.m = m;
        this.n = n;
        this.t = t;
        this.usePivots = usePivots;
        this.defaultKeySize = defaultKeySize;
        this.engine = new CMCEEngine(m, n, t, p, usePivots, defaultKeySize);
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

    public int getMu()
    {
        return (usePivots) ? 32 : 0;
    }

    public int getNu()
    {
        return (usePivots) ? 64 : 0;
    }

    public int getSessionKeySize()
    {
        return defaultKeySize;
    }

    CMCEEngine getEngine()
    {
        return engine;
    }
}
