package org.bouncycastle.pqc.crypto.cmce;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.util.Longs;

public class CMCEParameters
    implements CipherParameters
{
    private static int[] poly3488 = new int[]{3, 1, 0};
    private static int[] poly4608 = new int[]{10, 9, 6, 0};
    private static int[] poly6688 = new int[]{7, 2, 1, 0};
    private static int[] poly6960 = new int[]{8, 0};
    private static int[] poly8192 = new int[]{7, 2, 1, 0};

    public static final CMCEParameters mceliece348864 = new CMCEParameters("mceliece348864", 12, 3488, 64, poly3488, false);
    public static final CMCEParameters mceliece348864f = new CMCEParameters("mceliece348864f", 12, 3488, 64, poly3488, true);
    public static final CMCEParameters mceliece460896 = new CMCEParameters("mceliece460896", 13, 4608, 96, poly4608, false);
    public static final CMCEParameters mceliece460896f = new CMCEParameters("mceliece460896f", 13, 4608, 96, poly4608, true);
    public static final CMCEParameters mceliece6688128 = new CMCEParameters("mceliece6688128", 13, 6688, 128, poly6688, false);
    public static final CMCEParameters mceliece6688128f = new CMCEParameters("mceliece6688128f", 13, 6688, 128, poly6688, true);
    public static final CMCEParameters mceliece6960119 = new CMCEParameters("mceliece6960119", 13, 6960, 119, poly6960, false);
    public static final CMCEParameters mceliece6960119f = new CMCEParameters("mceliece6960119f", 13, 6960, 119, poly6960, true);
    public static final CMCEParameters mceliece8192128 = new CMCEParameters("mceliece8192128", 13, 8192, 128, poly8192, false);
    public static final CMCEParameters mceliece8192128f = new CMCEParameters("mceliece8192128f", 13, 8192, 128, poly8192, true);

    private static final Long cmce348864 = Longs.valueOf(0x0c0da0400000L);
    private static final Long cmce348864f = Longs.valueOf(0x0c0da0402040L);
    private static final Long cmce460896 = Longs.valueOf(0x0d1200600000L);
    private static final Long cmce460896f = Longs.valueOf(0x0d1200602040L);
    private static final Long cmce6688128 = Longs.valueOf(0x0d1a20800000L);
    private static final Long cmce6688128f = Longs.valueOf(0x0d1a20802040L);
    private static final Long cmce6960119 = Longs.valueOf(0x0d1b30770000L);
    private static final Long cmce6960119f = Longs.valueOf(0x0d1b30772040L);
    private static final Long cmce8192128 = Longs.valueOf(0x0d2000800000L);
    private static final Long cmce8192128f = Longs.valueOf(0x0d2000802040L);

    private static final Map oidToParams = new HashMap();
    private static final Map paramsToOid = new HashMap();

    static
    {
        oidToParams.put(cmce348864, mceliece348864);
        oidToParams.put(cmce348864f, mceliece348864f);
        oidToParams.put(cmce460896, mceliece460896);
        oidToParams.put(cmce460896f, mceliece460896f);
        oidToParams.put(cmce6688128, mceliece6688128);
        oidToParams.put(cmce6688128f, mceliece6688128f);
        oidToParams.put(cmce6960119, mceliece6960119);
        oidToParams.put(cmce6960119f, mceliece6960119f);
        oidToParams.put(cmce8192128, mceliece8192128);
        oidToParams.put(cmce8192128f, mceliece8192128f);

        paramsToOid.put(mceliece348864, cmce348864);
        paramsToOid.put(mceliece348864f, cmce348864f);
        paramsToOid.put(mceliece460896, cmce460896);
        paramsToOid.put(mceliece460896f, cmce460896f);
        paramsToOid.put(mceliece6688128, cmce6688128);
        paramsToOid.put(mceliece6688128f, cmce6688128f);
        paramsToOid.put(mceliece6960119, cmce6960119);
        paramsToOid.put(mceliece6960119f, cmce6960119f);
        paramsToOid.put(mceliece8192128, cmce8192128);
        paramsToOid.put(mceliece8192128f, cmce8192128f);
    }

    private final String name;
    private final int m;
    private final int n;
    private final int t;
    private final int[] poly;
    private final CMCEEngine engine;

    private CMCEParameters(String name, int m, int n, int t, int[] p, boolean usePivots)
    {
        this.name = name;
        this.m = m;
        this.n = n;
        this.t = t;
        this.poly = p;
        this.engine = new CMCEEngine(m, n, t, p, usePivots);
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
        return poly;
    }

    CMCEEngine getEngine()
    {
        return engine;
    }

    /**
     * Return the CMCE parameters that map to the passed in parameter ID.
     *
     * @param id the id of interest.
     * @return the parameter set.
     */
    public static CMCEParameters getParams(Long id)
    {
        return (CMCEParameters)oidToParams.get(id);
    }

    /**
     * Return the ID that maps to the passed in CMCE parameters.
     *
     * @param params the parameters of interest.
     * @return the ID for the parameter set.
     */
    public static Long getID(CMCEParameters params)
    {
        return (Long)paramsToOid.get(params);
    }
}
