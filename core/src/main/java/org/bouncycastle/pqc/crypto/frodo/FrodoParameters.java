package org.bouncycastle.pqc.crypto.frodo;

import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.pqc.crypto.KEMParameters;

public class FrodoParameters
    implements KEMParameters
{

    private static final short[] cdf_table640  = new short[]{4643, 13363, 20579, 25843, 29227, 31145, 32103, 32525, 32689, 32745, 32762, 32766, 32767};
    private static final short[] cdf_table976  = new short[]{5638, 15915, 23689, 28571, 31116, 32217, 32613, 32731, 32760, 32766, 32767};
    private static final short[] cdf_table1344 = new short[]{9142, 23462, 30338, 32361, 32725, 32765, 32767};

    public static final FrodoParameters frodokem640aes = new FrodoParameters("frodokem640aes", 640, 15, 2, cdf_table640, new SHAKEDigest(128), new FrodoMatrixGenerator.Aes128MatrixGenerator(640, (1<<15)));
    public static final FrodoParameters frodokem640shake = new FrodoParameters("frodokem640shake", 640, 15, 2, cdf_table640, new SHAKEDigest(128), new FrodoMatrixGenerator.Shake128MatrixGenerator(640, (1<<15)));

    public static final FrodoParameters frodokem976aes = new FrodoParameters("frodokem976aes", 976, 16, 3, cdf_table976, new SHAKEDigest(256), new FrodoMatrixGenerator.Aes128MatrixGenerator(976, (1<<16)));
    public static final FrodoParameters frodokem976shake = new FrodoParameters("frodokem976shake", 976, 16, 3, cdf_table976, new SHAKEDigest(256), new FrodoMatrixGenerator.Shake128MatrixGenerator(976, (1<<16)));

    public static final FrodoParameters frodokem1344aes = new FrodoParameters("frodokem1344aes", 1344, 16, 4, cdf_table1344, new SHAKEDigest(256), new FrodoMatrixGenerator.Aes128MatrixGenerator(1344, (1<<16)));
    public static final FrodoParameters frodokem1344shake = new FrodoParameters("frodokem1344shake", 1344, 16, 4, cdf_table1344, new SHAKEDigest(256), new FrodoMatrixGenerator.Shake128MatrixGenerator(1344, (1<<16)));

    private final String name;
    private final int n;
    private final int D;
    private final int B;
    private final int defaultKeySize;
    private final FrodoEngine engine;

    private FrodoParameters(String name, int n, int D, int B, short[] cdf_table, Xof digest, FrodoMatrixGenerator mGen)
    {
        this.name = name;
        this.n = n;
        this.D = D;
        this.B = B;
        this.defaultKeySize = B * FrodoEngine.nbar * FrodoEngine.nbar;
        this.engine = new FrodoEngine(n, D, B, cdf_table, digest, mGen);
    }

    public String getName()
    {
        return name;
    }

    public int getSessionKeySize()
    {
        return defaultKeySize;
    }

    FrodoEngine getEngine()
    {
        return engine;
    }

    int getN()
    {
        return n;
    }

    int getD()
    {
        return D;
    }

    int getB()
    {
        return B;
    }
}
