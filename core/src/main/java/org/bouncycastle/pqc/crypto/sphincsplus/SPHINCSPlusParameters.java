package org.bouncycastle.pqc.crypto.sphincsplus;

import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;

import java.util.HashMap;
import java.util.Map;

public class SPHINCSPlusParameters
{
    // SHA-2

    public static final SPHINCSPlusParameters sha2_128f = new SPHINCSPlusParameters(
        Integers.valueOf(0x010101), "sha2-128f-robust", new Sha2EngineProvider(true, 16, 16, 22, 6, 33, 66));
    public static final SPHINCSPlusParameters sha2_128s = new SPHINCSPlusParameters(
        Integers.valueOf(0x010102), "sha2-128s-robust", new Sha2EngineProvider(true, 16, 16, 7, 12, 14, 63));

    public static final SPHINCSPlusParameters sha2_192f = new SPHINCSPlusParameters(
        Integers.valueOf(0x010103), "sha2-192f-robust", new Sha2EngineProvider(true, 24, 16, 22, 8, 33, 66));
    public static final SPHINCSPlusParameters sha2_192s = new SPHINCSPlusParameters(
        Integers.valueOf(0x010104), "sha2-192s-robust", new Sha2EngineProvider(true, 24, 16, 7, 14, 17, 63));

    public static final SPHINCSPlusParameters sha2_256f = new SPHINCSPlusParameters(
        Integers.valueOf(0x010105), "sha2-256f-robust", new Sha2EngineProvider(true, 32, 16, 17, 9, 35, 68));
    public static final SPHINCSPlusParameters sha2_256s = new SPHINCSPlusParameters(
        Integers.valueOf(0x010106), "sha2-256s-robust", new Sha2EngineProvider(true, 32, 16, 8, 14, 22, 64));

    public static final SPHINCSPlusParameters sha2_128f_simple = new SPHINCSPlusParameters(
        Integers.valueOf(0x010201), "sha2-128f-simple", new Sha2EngineProvider(false, 16, 16, 22, 6, 33, 66));
    public static final SPHINCSPlusParameters sha2_128s_simple = new SPHINCSPlusParameters(
        Integers.valueOf(0x010202), "sha2-128s-simple", new Sha2EngineProvider(false, 16, 16, 7, 12, 14, 63));

    public static final SPHINCSPlusParameters sha2_192f_simple = new SPHINCSPlusParameters(
        Integers.valueOf(0x010203), "sha2-192f-simple", new Sha2EngineProvider(false, 24, 16, 22, 8, 33, 66));
    public static final SPHINCSPlusParameters sha2_192s_simple = new SPHINCSPlusParameters(
        Integers.valueOf(0x010204), "sha2-192s-simple", new Sha2EngineProvider(false, 24, 16, 7, 14, 17, 63));

    public static final SPHINCSPlusParameters sha2_256f_simple = new SPHINCSPlusParameters(
        Integers.valueOf(0x010205), "sha2-256f-simple", new Sha2EngineProvider(false, 32, 16, 17, 9, 35, 68));
    public static final SPHINCSPlusParameters sha2_256s_simple = new SPHINCSPlusParameters(
        Integers.valueOf(0x010206), "sha2-256s-simple", new Sha2EngineProvider(false, 32, 16, 8, 14, 22, 64));

    // SHAKE-256.

    public static final SPHINCSPlusParameters shake_128f = new SPHINCSPlusParameters(
        Integers.valueOf(0x020101), "shake-128f-robust", new Shake256EngineProvider(true, 16, 16, 22, 6, 33, 66));
    public static final SPHINCSPlusParameters shake_128s = new SPHINCSPlusParameters(
        Integers.valueOf(0x020102), "shake-128s-robust", new Shake256EngineProvider(true, 16, 16, 7, 12, 14, 63));

    public static final SPHINCSPlusParameters shake_192f = new SPHINCSPlusParameters(
        Integers.valueOf(0x020103), "shake-192f-robust", new Shake256EngineProvider(true, 24, 16, 22, 8, 33, 66));
    public static final SPHINCSPlusParameters shake_192s = new SPHINCSPlusParameters(
        Integers.valueOf(0x020104), "shake-192s-robust", new Shake256EngineProvider(true, 24, 16, 7, 14, 17, 63));

    public static final SPHINCSPlusParameters shake_256f = new SPHINCSPlusParameters(
        Integers.valueOf(0x020105), "shake-256f-robust", new Shake256EngineProvider(true, 32, 16, 17, 9, 35, 68));
    public static final SPHINCSPlusParameters shake_256s = new SPHINCSPlusParameters(
        Integers.valueOf(0x020106), "shake-256s-robust", new Shake256EngineProvider(true, 32, 16, 8, 14, 22, 64));

    public static final SPHINCSPlusParameters shake_128f_simple = new SPHINCSPlusParameters(
        Integers.valueOf(0x020201), "shake-128f-simple", new Shake256EngineProvider(false, 16, 16, 22, 6, 33, 66));
    public static final SPHINCSPlusParameters shake_128s_simple = new SPHINCSPlusParameters(
        Integers.valueOf(0x020202), "shake-128s-simple", new Shake256EngineProvider(false, 16, 16, 7, 12, 14, 63));

    public static final SPHINCSPlusParameters shake_192f_simple = new SPHINCSPlusParameters(
        Integers.valueOf(0x020203), "shake-192f-simple", new Shake256EngineProvider(false, 24, 16, 22, 8, 33, 66));
    public static final SPHINCSPlusParameters shake_192s_simple = new SPHINCSPlusParameters(
        Integers.valueOf(0x020204), "shake-192s-simple", new Shake256EngineProvider(false, 24, 16, 7, 14, 17, 63));

    public static final SPHINCSPlusParameters shake_256f_simple = new SPHINCSPlusParameters(
        Integers.valueOf(0x020205), "shake-256f-simple", new Shake256EngineProvider(false, 32, 16, 17, 9, 35, 68));
    public static final SPHINCSPlusParameters shake_256s_simple = new SPHINCSPlusParameters(
        Integers.valueOf(0x020206), "shake-256s-simple", new Shake256EngineProvider(false, 32, 16, 8, 14, 22, 64));

    // Haraka.

    /**
     * @deprecated
     * obsolete to be removed
     */
    @Deprecated
    public static final SPHINCSPlusParameters haraka_128f = new SPHINCSPlusParameters(
        Integers.valueOf(0x030101), "haraka-128f-robust", new HarakaSEngineProvider(true, 16, 16, 22, 6, 33, 66));
    @Deprecated
    public static final SPHINCSPlusParameters haraka_128s = new SPHINCSPlusParameters(
        Integers.valueOf(0x030102), "haraka-128s-robust", new HarakaSEngineProvider(true, 16, 16, 7, 12, 14, 63));
    @Deprecated
    public static final SPHINCSPlusParameters haraka_192f = new SPHINCSPlusParameters(
        Integers.valueOf(0x030103), "haraka-192f-robust", new HarakaSEngineProvider(true, 24, 16, 22, 8, 33, 66));
    @Deprecated
    public static final SPHINCSPlusParameters haraka_192s = new SPHINCSPlusParameters(
        Integers.valueOf(0x030104), "haraka-192s-robust", new HarakaSEngineProvider(true, 24, 16, 7, 14, 17, 63));
    @Deprecated
    public static final SPHINCSPlusParameters haraka_256f = new SPHINCSPlusParameters(
        Integers.valueOf(0x030105), "haraka-256f-robust", new HarakaSEngineProvider(true, 32, 16, 17, 9, 35, 68));
    @Deprecated
    public static final SPHINCSPlusParameters haraka_256s = new SPHINCSPlusParameters(
        Integers.valueOf(0x030106), "haraka-256s-robust", new HarakaSEngineProvider(true, 32, 16, 8, 14, 22, 64));

    public static final SPHINCSPlusParameters haraka_128f_simple = new SPHINCSPlusParameters(
        Integers.valueOf(0x030201), "haraka-128f-simple", new HarakaSEngineProvider(false, 16, 16, 22, 6, 33, 66));
    public static final SPHINCSPlusParameters haraka_128s_simple = new SPHINCSPlusParameters(
        Integers.valueOf(0x030202), "haraka-128s-simple", new HarakaSEngineProvider(false, 16, 16, 7, 12, 14, 63));

    public static final SPHINCSPlusParameters haraka_192f_simple = new SPHINCSPlusParameters(
        Integers.valueOf(0x030203), "haraka-192f-simple", new HarakaSEngineProvider(false, 24, 16, 22, 8, 33, 66));
    public static final SPHINCSPlusParameters haraka_192s_simple = new SPHINCSPlusParameters(
        Integers.valueOf(0x030204), "haraka-192s-simple", new HarakaSEngineProvider(false, 24, 16, 7, 14, 17, 63));

    public static final SPHINCSPlusParameters haraka_256f_simple = new SPHINCSPlusParameters(
        Integers.valueOf(0x030205), "haraka-256f-simple", new HarakaSEngineProvider(false, 32, 16, 17, 9, 35, 68));
    public static final SPHINCSPlusParameters haraka_256s_simple = new SPHINCSPlusParameters(
        Integers.valueOf(0x030206), "haraka-256s-simple", new HarakaSEngineProvider(false, 32, 16, 8, 14, 22, 64));

    private static final Map<Integer, SPHINCSPlusParameters> ID_TO_PARAMS = new HashMap<Integer, SPHINCSPlusParameters>();

    static
    {
        SPHINCSPlusParameters[] all = new SPHINCSPlusParameters[]{
            SPHINCSPlusParameters.sha2_128f, SPHINCSPlusParameters.sha2_128s,
            SPHINCSPlusParameters.sha2_192f, SPHINCSPlusParameters.sha2_192s,
            SPHINCSPlusParameters.sha2_256f, SPHINCSPlusParameters.sha2_256s,
            SPHINCSPlusParameters.sha2_128f_simple, SPHINCSPlusParameters.sha2_128s_simple,
            SPHINCSPlusParameters.sha2_192f_simple, SPHINCSPlusParameters.sha2_192s_simple,
            SPHINCSPlusParameters.sha2_256f_simple, SPHINCSPlusParameters.sha2_256s_simple,
            SPHINCSPlusParameters.shake_128f, SPHINCSPlusParameters.shake_128s,
            SPHINCSPlusParameters.shake_192f, SPHINCSPlusParameters.shake_192s,
            SPHINCSPlusParameters.shake_256f, SPHINCSPlusParameters.shake_256s,
            SPHINCSPlusParameters.shake_128f_simple, SPHINCSPlusParameters.shake_128s_simple,
            SPHINCSPlusParameters.shake_192f_simple, SPHINCSPlusParameters.shake_192s_simple,
            SPHINCSPlusParameters.shake_256f_simple, SPHINCSPlusParameters.shake_256s_simple,
            SPHINCSPlusParameters.haraka_128f, SPHINCSPlusParameters.haraka_128s,
            SPHINCSPlusParameters.haraka_192f, SPHINCSPlusParameters.haraka_192s,
            SPHINCSPlusParameters.haraka_256f, SPHINCSPlusParameters.haraka_256s,
            SPHINCSPlusParameters.haraka_128f_simple, SPHINCSPlusParameters.haraka_128s_simple,
            SPHINCSPlusParameters.haraka_192f_simple, SPHINCSPlusParameters.haraka_192s_simple,
            SPHINCSPlusParameters.haraka_256f_simple, SPHINCSPlusParameters.haraka_256s_simple,
        };

        for (int i = 0; i < all.length; ++i)
        {
            SPHINCSPlusParameters parameters = all[i];
            ID_TO_PARAMS.put(parameters.getID(), parameters);
        }
    }

    private final Integer id;
    private final String name;
    private final SPHINCSPlusEngineProvider engineProvider;

    private SPHINCSPlusParameters(Integer id, String name, SPHINCSPlusEngineProvider engineProvider)
    {
        this.id = id;
        this.name = name;
        this.engineProvider = engineProvider;
    }

    public Integer getID()
    {
        return id;
    }

    public String getName()
    {
        return name;
    }

    int getN()
    {
        return engineProvider.getN();
    }

    SPHINCSPlusEngine getEngine()
    {
        return engineProvider.get();
    }

    /**
     * Return the SPHINCS+ parameters that map to the passed in parameter ID.
     *
     * @param id the oid of interest.
     * @return the parameter set.
     */
    public static SPHINCSPlusParameters getParams(Integer id)
    {
        return (SPHINCSPlusParameters)ID_TO_PARAMS.get(id);
    }

    /**
     * Return the OID that maps to the passed in SPHINCS+ parameters.
     *
     * @param params the parameters of interest.
     * @return the OID for the parameter set.
     * @deprecated Use {@link #getID()} instead
     */
    public static Integer getID(SPHINCSPlusParameters params)
    {
        return params.getID();
    }

    public byte[] getEncoded()
    {
        return Pack.intToBigEndian(getID().intValue());
    }

    private static class Sha2EngineProvider
        implements SPHINCSPlusEngineProvider
    {
        private final boolean robust;
        private final int n;
        private final int w;
        private final int d;
        private final int a;
        private final int k;
        private final int h;

        public Sha2EngineProvider(boolean robust, int n, int w, int d, int a, int k, int h)
        {
            this.robust = robust;
            this.n = n;
            this.w = w;
            this.d = d;
            this.a = a;
            this.k = k;
            this.h = h;
        }

        public int getN()
        {
            return n;
        }

        public SPHINCSPlusEngine get()
        {
            return new SPHINCSPlusEngine.Sha2Engine(robust, n, w, d, a, k, h);
        }
    }

    private static class Shake256EngineProvider
        implements SPHINCSPlusEngineProvider
    {
        private final boolean robust;
        private final int n;
        private final int w;
        private final int d;
        private final int a;
        private final int k;
        private final int h;

        public Shake256EngineProvider(boolean robust, int n, int w, int d, int a, int k, int h)
        {
            this.robust = robust;
            this.n = n;
            this.w = w;
            this.d = d;
            this.a = a;
            this.k = k;
            this.h = h;
        }

        public int getN()
        {
            return n;
        }

        public SPHINCSPlusEngine get()
        {
            return new SPHINCSPlusEngine.Shake256Engine(robust, n, w, d, a, k, h);
        }
    }

    private static class HarakaSEngineProvider
        implements SPHINCSPlusEngineProvider
    {
        private final boolean robust;
        private final int n;
        private final int w;
        private final int d;
        private final int a;
        private final int k;
        private final int h;

        public HarakaSEngineProvider(boolean robust, int n, int w, int d, int a, int k, int h)
        {
            this.robust = robust;
            this.n = n;
            this.w = w;
            this.d = d;
            this.a = a;
            this.k = k;
            this.h = h;
        }

        public int getN()
        {
            return n;
        }

        public SPHINCSPlusEngine get()
        {
            return new SPHINCSPlusEngine.HarakaSEngine(robust, n, w, d, a, k, h);
        }
    }
}
