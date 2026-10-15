package org.bouncycastle.pqc.crypto.hqc;

import org.bouncycastle.pqc.crypto.KEMParameters;

/**
 * Parameter sets of the HQC specification of 2026-10-12 (Tables 6, 8 and 9): n, n1, n2, k, delta, the
 * weights omega and omega_r (= omega_e), the FFT exponent, the Barrett multiplier for n, the size of
 * ekKEM and the Reed-Solomon generator polynomial over GF(2^8) = GF(2)[X]/(X^8 + X^4 + X^3 + X + 1).
 */
public class HQCParameters
    implements KEMParameters
{
    // 128 bits security
    public static final HQCParameters hqc128 = new HQCParameters("hqc-128", 17669, 46, 384, 16,
        15, 67, 76, 4, 243079, 2241,
        new int[]{74, 81, 224, 114, 221, 115, 110, 88, 91, 151, 139, 151, 84, 184, 21, 242, 97, 199, 87, 113, 104, 184, 197, 111, 89, 81, 156, 71, 128, 217, 1});

    // 192 bits security
    public static final HQCParameters hqc192 = new HQCParameters("hqc-192", 35851, 56, 640, 24,
        16, 101, 114, 5, 119800, 4514,
        new int[]{56, 180, 145, 30, 131, 105, 28, 60, 107, 33, 206, 184, 155, 249, 153, 231, 112, 11, 231, 1, 144, 201, 71, 62, 8, 150, 142, 246, 33, 214, 26, 150, 1});

    // 256 bits security
    public static final HQCParameters hqc256 = new HQCParameters("hqc-256", 57637, 90, 640, 32,
        29, 132, 150, 5, 74517, 7237,
        new int[]{35, 203, 35, 52, 165, 121, 125, 73, 136, 42, 235, 82, 232, 122, 67, 98, 51, 188, 230, 82, 164, 117, 103, 184, 209, 218, 244, 181, 122, 10, 25, 138, 216, 182, 225, 145, 100, 244, 5, 142, 213, 238, 15, 150, 59, 28, 244, 222, 252, 85, 125, 59, 52, 215, 180, 34, 173, 208, 1});

    static final int PARAM_M = 8;
    static final int GF_MUL_ORDER = 255;

    private final String name;
    private final int n;
    private final int n1;
    private final int n2;

    private final int publicKeyBytes;

    private final HQCEngine engine;

    private HQCParameters(String name, int n, int n1, int n2, int k, int delta, int w, int wr, int fft, int nMu,
        int pkSize, int[] generatorPoly)
    {
        this.name = name;
        this.n = n;
        this.n1 = n1;
        this.n2 = n2;
        this.publicKeyBytes = pkSize;
        this.engine = new HQCEngine(n, n1, n2, k, delta, w, wr, fft, nMu, pkSize, generatorPoly);
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
        return engine;
    }

    public int getEncapsulationLength()
    {
        return engine.getCipherTextBytes();
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

    /**
     * Return the size of the decapsulation key encoding: the 32-byte seedKEM from which the whole key
     * pair is derived, which is the only dkKEM format of the HQC specification of 2026-10-12.
     *
     * @return 32.
     */
    public int getSecretKeyBytes()
    {
        return HQCEngine.SEED_BYTES;
    }

    public int getSecretLength()
    {
        return HQCEngine.SHARED_SECRET_BYTES;
    }
}
