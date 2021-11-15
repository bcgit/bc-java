package org.bouncycastle.pqc.crypto.sphincsplus;

public class SPHINCSPlusParameters
{
    public static final SPHINCSPlusParameters sha256_128f = new SPHINCSPlusParameters(new SPHINCSPlusEngine.Sha256Engine(true, 16, 16, 22, 6, 33, 66));
    public static final SPHINCSPlusParameters sha256_128s = new SPHINCSPlusParameters(new SPHINCSPlusEngine.Sha256Engine(true, 16, 16, 7, 12, 14, 63));

    public static final SPHINCSPlusParameters sha256_192f = new SPHINCSPlusParameters(new SPHINCSPlusEngine.Sha256Engine(true, 24, 16, 22, 8, 33, 66));
    public static final SPHINCSPlusParameters sha256_192s = new SPHINCSPlusParameters(new SPHINCSPlusEngine.Sha256Engine(true, 24, 16, 7, 14, 17, 63));

    public static final SPHINCSPlusParameters sha256_256f = new SPHINCSPlusParameters(new SPHINCSPlusEngine.Sha256Engine(true, 32, 16, 17, 9, 35, 68));
    public static final SPHINCSPlusParameters sha256_256s = new SPHINCSPlusParameters(new SPHINCSPlusEngine.Sha256Engine(true, 32, 16, 8, 14, 22, 64));

    public static final SPHINCSPlusParameters sha256_128f_simple = new SPHINCSPlusParameters(new SPHINCSPlusEngine.Sha256Engine(false, 16, 16, 22, 6, 33, 66));
    public static final SPHINCSPlusParameters sha256_128s_simple = new SPHINCSPlusParameters(new SPHINCSPlusEngine.Sha256Engine(false, 16, 16, 7, 12, 14, 63));

    public static final SPHINCSPlusParameters sha256_192f_simple = new SPHINCSPlusParameters(new SPHINCSPlusEngine.Sha256Engine(false, 24, 16, 22, 8, 33, 66));
    public static final SPHINCSPlusParameters sha256_192s_simple = new SPHINCSPlusParameters(new SPHINCSPlusEngine.Sha256Engine(false, 24, 16, 7, 14, 17, 63));

    public static final SPHINCSPlusParameters sha256_256f_simple = new SPHINCSPlusParameters(new SPHINCSPlusEngine.Sha256Engine(false, 32, 16, 17, 9, 35, 68));
    public static final SPHINCSPlusParameters sha256_256s_simple = new SPHINCSPlusParameters(new SPHINCSPlusEngine.Sha256Engine(false, 32, 16, 8, 14, 22, 64));

    // SHAKE-256.

    public static final SPHINCSPlusParameters shake256_128f = new SPHINCSPlusParameters(new SPHINCSPlusEngine.Shake256Engine(true, 16, 16, 22, 6, 33, 66));
    public static final SPHINCSPlusParameters shake256_128s = new SPHINCSPlusParameters(new SPHINCSPlusEngine.Shake256Engine(true, 16, 16, 7, 12, 14, 63));

    public static final SPHINCSPlusParameters shake256_192f = new SPHINCSPlusParameters(new SPHINCSPlusEngine.Shake256Engine(true, 24, 16, 22, 8, 33, 66));
    public static final SPHINCSPlusParameters shake256_192s = new SPHINCSPlusParameters(new SPHINCSPlusEngine.Shake256Engine(true, 24, 16, 7, 14, 17, 63));

    public static final SPHINCSPlusParameters shake256_256f = new SPHINCSPlusParameters(new SPHINCSPlusEngine.Shake256Engine(true, 32, 16, 17, 9, 35, 68));
    public static final SPHINCSPlusParameters shake256_256s = new SPHINCSPlusParameters(new SPHINCSPlusEngine.Shake256Engine(true, 32, 16, 8, 14, 22, 64));

    public static final SPHINCSPlusParameters shake256_128f_simple = new SPHINCSPlusParameters(new SPHINCSPlusEngine.Shake256Engine(false, 16, 16, 22, 6, 33, 66));
    public static final SPHINCSPlusParameters shake256_128s_simple = new SPHINCSPlusParameters(new SPHINCSPlusEngine.Shake256Engine(false, 16, 16, 7, 12, 14, 63));

    public static final SPHINCSPlusParameters shake256_192f_simple = new SPHINCSPlusParameters(new SPHINCSPlusEngine.Shake256Engine(false, 24, 16, 22, 8, 33, 66));
    public static final SPHINCSPlusParameters shake256_192s_simple = new SPHINCSPlusParameters(new SPHINCSPlusEngine.Shake256Engine(false, 24, 16, 7, 14, 17, 63));

    public static final SPHINCSPlusParameters shake256_256f_simple = new SPHINCSPlusParameters(new SPHINCSPlusEngine.Shake256Engine(false, 32, 16, 17, 9, 35, 68));
    public static final SPHINCSPlusParameters shake256_256s_simple = new SPHINCSPlusParameters(new SPHINCSPlusEngine.Shake256Engine(false, 32, 16, 8, 14, 22, 64));

    private final SPHINCSPlusEngine engine;

    private SPHINCSPlusParameters(SPHINCSPlusEngine engine)
    {
        this.engine = engine;
    }

    SPHINCSPlusEngine getEngine()
    {
        return engine;
    }
}
