package org.bouncycastle.pqc.crypto.frodo;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHAKEDigest;

public class FrodoParameters
    implements CipherParameters
{

    private static final short[] cdf_table640  = new short[]{4643, 13363, 20579, 25843, 29227, 31145, 32103, 32525, 32689, 32745, 32762, 32766, 32767};
    private static final short[] cdf_table976  = new short[]{5638, 15915, 23689, 28571, 31116, 32217, 32613, 32731, 32760, 32766, 32767};
    private static final short[] cdf_table1344 = new short[]{9142, 23462, 30338, 32361, 32725, 32765, 32767};

    public static final FrodoParameters frodokem19888r3 = new FrodoParameters("frodokem19888", 640, 15, 2, cdf_table640, new SHAKEDigest(128), new FrodoMatrixGenerator.Aes128MatrixGenerator(640, (1<<15)), 64);
    public static final FrodoParameters frodokem19888shaker3 = new FrodoParameters("frodokem19888shake", 640, 15, 2, cdf_table640, new SHAKEDigest(128), new FrodoMatrixGenerator.Shake128MatrixGenerator(640, (1<<15)), 64);

    public static final FrodoParameters frodokem31296r3 = new FrodoParameters("frodokem31296", 976, 16, 3, cdf_table976, new SHAKEDigest(256), new FrodoMatrixGenerator.Aes128MatrixGenerator(976, (1<<16)), 96);
    public static final FrodoParameters frodokem31296shaker3 = new FrodoParameters("frodokem31296shake", 976, 16, 3, cdf_table976, new SHAKEDigest(256), new FrodoMatrixGenerator.Shake128MatrixGenerator(976, (1<<16)), 96);

    public static final FrodoParameters frodokem43088r3 = new FrodoParameters("frodokem43088", 1344, 16, 4, cdf_table1344, new SHAKEDigest(256), new FrodoMatrixGenerator.Aes128MatrixGenerator(1344, (1<<16)), 128);
    public static final FrodoParameters frodokem43088shaker3 = new FrodoParameters("frodokem43088shake", 1344, 16, 4, cdf_table1344, new SHAKEDigest(256), new FrodoMatrixGenerator.Shake128MatrixGenerator(1344, (1<<16)), 128);

    private final String name;
    private final int n;
    private final int D;
    private final int B;
    private final short[] cdf_table;
    private final Xof digest;
    private final FrodoMatrixGenerator mGen;
    private final int defaultKeySize;
    private final FrodoEngine engine;

    public FrodoParameters(String name, int n, int D, int B, short[] cdf_table, Xof digest, FrodoMatrixGenerator mGen, int defaultKeySize)
    {
        this.name = name;
        this.n = n;
        this.D = D;
        this.B = B;
        this.cdf_table = cdf_table;
        this.digest = digest;
        this.mGen = mGen;
        this.defaultKeySize = defaultKeySize;
        this.engine = new FrodoEngine(n, D, B, cdf_table, digest, mGen);
    }

    FrodoEngine getEngine()
    {
        return engine;
    }

    public int getN()
    {
        return n;
    }

    public String getName()
    {
        return name;
    }

    public int getD()
    {
        return D;
    }

    public int getB()
    {
        return B;
    }

    public short[] getCdf_table()
    {
        return cdf_table;
    }

    public Xof getDigest()
    {
        return digest;
    }

    public int getDefaultKeySize()
    {
        return defaultKeySize;
    }

    public FrodoMatrixGenerator getmGen()
    {
        return mGen;
    }
}
