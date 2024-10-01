package org.bouncycastle.pqc.crypto.slhdsa;

public class SLHDSAParameters
{
    public static final int TYPE_PURE = 0;
    public static final int TYPE_SHA2_256 = 1;
    public static final int TYPE_SHA2_512 = 2;
    public static final int TYPE_SHAKE128 = 3;
    public static final int TYPE_SHAKE256 = 4;

    // "Pure" SLH-DSA Parameters
    // SHA-2
    public static final SLHDSAParameters sha2_128f = new SLHDSAParameters(
        "sha2-128f", new Sha2EngineProvider(16, 16, 22, 6, 33, 66), TYPE_PURE);
    public static final SLHDSAParameters sha2_128s = new SLHDSAParameters(
        "sha2-128s", new Sha2EngineProvider(16, 16, 7, 12, 14, 63), TYPE_PURE);

    public static final SLHDSAParameters sha2_192f = new SLHDSAParameters(
        "sha2-192f", new Sha2EngineProvider(24, 16, 22, 8, 33, 66), TYPE_PURE);
    public static final SLHDSAParameters sha2_192s = new SLHDSAParameters(
        "sha2-192s", new Sha2EngineProvider(24, 16, 7, 14, 17, 63), TYPE_PURE);

    public static final SLHDSAParameters sha2_256f = new SLHDSAParameters(
        "sha2-256f", new Sha2EngineProvider(32, 16, 17, 9, 35, 68), TYPE_PURE);
    public static final SLHDSAParameters sha2_256s = new SLHDSAParameters(
        "sha2-256s", new Sha2EngineProvider(32, 16, 8, 14, 22, 64), TYPE_PURE);

    // SHAKE-256.
    public static final SLHDSAParameters shake_128f = new SLHDSAParameters(
        "shake-128f", new Shake256EngineProvider(16, 16, 22, 6, 33, 66), TYPE_PURE);
    public static final SLHDSAParameters shake_128s = new SLHDSAParameters(
        "shake-128s", new Shake256EngineProvider(16, 16, 7, 12, 14, 63), TYPE_PURE);

    public static final SLHDSAParameters shake_192f = new SLHDSAParameters(
        "shake-192f", new Shake256EngineProvider(24, 16, 22, 8, 33, 66), TYPE_PURE);
    public static final SLHDSAParameters shake_192s = new SLHDSAParameters(
        "shake-192s", new Shake256EngineProvider(24, 16, 7, 14, 17, 63), TYPE_PURE);

    public static final SLHDSAParameters shake_256f = new SLHDSAParameters(
        "shake-256f", new Shake256EngineProvider(32, 16, 17, 9, 35, 68), TYPE_PURE);
    public static final SLHDSAParameters shake_256s = new SLHDSAParameters(
        "shake-256s", new Shake256EngineProvider(32, 16, 8, 14, 22, 64), TYPE_PURE);


    // "Pre-hash" SLH-DSA Parameters
    // SHA-2
    public static final SLHDSAParameters sha2_128f_with_sha256 = new SLHDSAParameters(
        "sha2-128f-with-sha256", new Sha2EngineProvider(16, 16, 22, 6, 33, 66), TYPE_SHA2_256);
    public static final SLHDSAParameters sha2_128s_with_sha256 = new SLHDSAParameters(
        "sha2-128s-with-sha256", new Sha2EngineProvider(16, 16, 7, 12, 14, 63), TYPE_SHA2_256);

    public static final SLHDSAParameters sha2_192f_with_sha512 = new SLHDSAParameters(
        "sha2-192f-with-sha512", new Sha2EngineProvider(24, 16, 22, 8, 33, 66), TYPE_SHA2_512);
    public static final SLHDSAParameters sha2_192s_with_sha512 = new SLHDSAParameters(
        "sha2-192s-with-sha512", new Sha2EngineProvider(24, 16, 7, 14, 17, 63), TYPE_SHA2_512);

    public static final SLHDSAParameters sha2_256f_with_sha512 = new SLHDSAParameters(
        "sha2-256f-with-sha512", new Sha2EngineProvider(32, 16, 17, 9, 35, 68), TYPE_SHA2_512);
    public static final SLHDSAParameters sha2_256s_with_sha512 = new SLHDSAParameters(
        "sha2-256s-with-sha512", new Sha2EngineProvider(32, 16, 8, 14, 22, 64), TYPE_SHA2_512);

    // SHAKE-256.
    public static final SLHDSAParameters shake_128f_with_shake128 = new SLHDSAParameters(
        "shake-128f-with-shake128", new Shake256EngineProvider(16, 16, 22, 6, 33, 66), TYPE_SHAKE128);
    public static final SLHDSAParameters shake_128s_with_shake128 = new SLHDSAParameters(
        "shake-128s-with-shake128", new Shake256EngineProvider(16, 16, 7, 12, 14, 63), TYPE_SHAKE128);

    public static final SLHDSAParameters shake_192f_with_shake256 = new SLHDSAParameters(
        "shake-192f-with-shake256", new Shake256EngineProvider(24, 16, 22, 8, 33, 66), TYPE_SHAKE256);
    public static final SLHDSAParameters shake_192s_with_shake256 = new SLHDSAParameters(
        "shake-192s-with-shake256", new Shake256EngineProvider(24, 16, 7, 14, 17, 63), TYPE_SHAKE256);

    public static final SLHDSAParameters shake_256f_with_shake256 = new SLHDSAParameters(
        "shake-256f-with-shake256", new Shake256EngineProvider(32, 16, 17, 9, 35, 68), TYPE_SHAKE256);
    public static final SLHDSAParameters shake_256s_with_shake256 = new SLHDSAParameters(
        "shake-256s-with-shake256", new Shake256EngineProvider(32, 16, 8, 14, 22, 64), TYPE_SHAKE256);

    private final String name;
    private final SLHDSAEngineProvider engineProvider;
    private final int preHashDigest;

    private SLHDSAParameters(String name, SLHDSAEngineProvider engineProvider, int preHashDigest)
    {
        this.name = name;
        this.engineProvider = engineProvider;
        this.preHashDigest = preHashDigest;
    }

    public String getName()
    {
        return name;
    }

    public int getType()
    {
        return preHashDigest;
    }

    int getN()
    {
        return engineProvider.getN();
    }

    SLHDSAEngine getEngine()
    {
        return engineProvider.get();
    }

    public boolean isPreHash()
    {
        return preHashDigest != TYPE_PURE;
    }

    private static class Sha2EngineProvider
        implements SLHDSAEngineProvider
    {
        private final int n;
        private final int w;
        private final int d;
        private final int a;
        private final int k;
        private final int h;

        public Sha2EngineProvider(int n, int w, int d, int a, int k, int h)
        {
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

        public SLHDSAEngine get()
        {
            return new SLHDSAEngine.Sha2Engine(n, w, d, a, k, h);
        }
    }

    private static class Shake256EngineProvider
        implements SLHDSAEngineProvider
    {
        private final int n;
        private final int w;
        private final int d;
        private final int a;
        private final int k;
        private final int h;

        public Shake256EngineProvider(int n, int w, int d, int a, int k, int h)
        {
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

        public SLHDSAEngine get()
        {
            return new SLHDSAEngine.Shake256Engine(n, w, d, a, k, h);
        }
    }
}
