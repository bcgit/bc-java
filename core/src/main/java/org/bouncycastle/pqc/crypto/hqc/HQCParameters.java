package org.bouncycastle.pqc.crypto.hqc;

import org.bouncycastle.pqc.crypto.KEMParameters;

public class HQCParameters
    implements KEMParameters
{
    // 128 bits security
    public static final HQCParameters hqc128 = new HQCParameters("hqc-128", 17669, 46, 384, 16,
        31, 15, 66, 75, 4, 243079, 2241, 2321,
        new int[]{89, 69, 153, 116, 176, 117, 111, 75, 73, 233, 242, 233, 65, 210, 21, 139, 103, 173, 67, 118, 105, 210, 174, 110, 74, 69, 228, 82, 255, 181, 1});

    // 192 bits security
    public static final HQCParameters hqc192 = new HQCParameters("hqc-192", 35851, 56, 640, 24,
        33, 16, 100, 114, 5, 119800, 4514, 4602,
        new int[]{45, 216, 239, 24, 253, 104, 27, 40, 107, 50, 163, 210, 227, 134, 224, 158, 119, 13, 158, 1, 238, 164, 82, 43, 15, 232, 246, 142, 50, 189, 29, 232, 1});

    // 256 bits security
    public static final HQCParameters hqc256 = new HQCParameters("hqc-256", 57637, 90, 640, 32,
        59, 29, 131, 149, 5, 74517, 7237, 7333,
        new int[]{49, 167, 49, 39, 200, 121, 124, 91, 240, 63, 148, 71, 150, 123, 87, 101, 32, 215, 159, 71, 201, 115, 97, 210, 186, 183, 141, 217, 123, 12, 31, 243, 180, 219, 152, 239, 99, 141, 4, 246, 191, 144, 8, 232, 47, 27, 141, 178, 130, 64, 124, 47, 39, 188, 216, 48, 199, 187, 1});

    private final String name;
    private final int n;
    private final int n1;
    private final int n2;

    private final int publicKeyBytes;
    private final int secretKeyBytes;

    final static int PARAM_M = 8;
    final static int GF_MUL_ORDER = 255;

    private final HQCEngine hqcEngine;

    private HQCParameters(String name, int n, int n1, int n2, int k, int g, int delta, int w, int wr,
                          int fft, int nMu, int pkSize, int skSize, int[] generatorPoly)
    {
        this.name = name;
        this.n = n;
        this.n1 = n1;
        this.n2 = n2;
        this.publicKeyBytes = pkSize;
        this.secretKeyBytes = skSize;
        hqcEngine = new HQCEngine(n, n1, n2, k, g, delta, w, wr, fft, nMu, pkSize, generatorPoly);
    }

    int getSHA512_BYTES()
    {
        return 512 / 8;
    }

    int getSALT_SIZE_BYTES()
    {
        return 16;
    }

    int getN_BYTES()
    {
        return (n + 7) / 8;
    }

    int getN1N2_BYTES()
    {
        return (n1 * n2 + 7) / 8;
    }

    HQCEngine getEngine()
    {
        return hqcEngine;
    }

    public int getSessionKeySize()
    {
        return 32 * 8;
    }

    public String getName()
    {
        return name;
    }

    public int getPublicKeyBytes()
    {
        return publicKeyBytes;
    }

    public int getSecretKeyBytes()
    {
        return secretKeyBytes;
    }
}
