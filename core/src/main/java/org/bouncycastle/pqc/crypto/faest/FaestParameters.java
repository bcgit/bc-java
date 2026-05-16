package org.bouncycastle.pqc.crypto.faest;

/**
 * FAEST parameter sets per the v2.0 algorithm specification.
 * <p>
 * Twelve instances are exposed, one per parameter set, mirroring the
 * {@code faest_paramid_t} enumeration in the reference implementation's
 * {@code instances.h}. Numeric values come from the per-parameter macros in
 * {@code build/parameters.h} of the reference build (auto-generated from the
 * spec). The "derived" fields ({@code k}, {@code tau0}, {@code tau1}, {@code L})
 * are computed from {@code lambda}, {@code tau}, {@code wGrind} per the
 * formulae in {@code instances.c}.
 * <p>
 * Reference upstream: {@code faest-sign/faest-ref}.
 */
public final class FaestParameters
{
    // ----- Base FAEST (AES one-way function) -----

    /**
     * FAEST-128s: lambda=128, small-signature trade-off. Signature 4506 bytes.
     */
    public static final FaestParameters faest_128s = new FaestParameters(
        "faest_128s", false,
        /* lambda */ 128, /* tau */ 11, /* wGrind */ 7,  /* tOpen */ 102,
        /* ell    */ 1280,
        /* Nst */ 4, /* Ske */ 40, /* R */ 10, /* Senc */ 160,
        /* Lke */ 448, /* Lenc */ 832, /* C */ 321,
        /* beta */ 1, /* owfIn */ 16, /* owfOut */ 16,
        /* pkSize */ 32, /* skSize */ 32, /* sigSize */ 4506);

    /**
     * FAEST-128f: lambda=128, fast-signing trade-off. Signature 5924 bytes.
     */
    public static final FaestParameters faest_128f = new FaestParameters(
        "faest_128f", false,
        128, 16, 8, 110, 1280,
        4, 40, 10, 160, 448, 832, 321,
        1, 16, 16, 32, 32, 5924);

    /**
     * FAEST-192s: lambda=192, small-signature trade-off. Signature 11260 bytes.
     */
    public static final FaestParameters faest_192s = new FaestParameters(
        "faest_192s", false,
        192, 16, 12, 162, 2496,
        4, 32, 12, 192, 448, 1024, 641,
        2, 16, 32, 48, 40, 11260);

    /**
     * FAEST-192f: lambda=192, fast-signing trade-off. Signature 14948 bytes.
     */
    public static final FaestParameters faest_192f = new FaestParameters(
        "faest_192f", false,
        192, 24, 8, 163, 2496,
        4, 32, 12, 192, 448, 1024, 641,
        2, 16, 32, 48, 40, 14948);

    /**
     * FAEST-256s: lambda=256, small-signature trade-off. Signature 20696 bytes.
     */
    public static final FaestParameters faest_256s = new FaestParameters(
        "faest_256s", false,
        256, 22, 6, 245, 3104,
        4, 52, 14, 224, 672, 1216, 777,
        2, 16, 32, 48, 48, 20696);

    /**
     * FAEST-256f: lambda=256, fast-signing trade-off. Signature 26548 bytes.
     */
    public static final FaestParameters faest_256f = new FaestParameters(
        "faest_256f", false,
        256, 32, 8, 246, 3104,
        4, 52, 14, 224, 672, 1216, 777,
        2, 16, 32, 48, 48, 26548);

    // ----- FAEST-EM (Even-Mansour one-way function) -----

    /**
     * FAEST-EM-128s: lambda=128, EM mode, small-signature trade-off. Signature 3906 bytes.
     */
    public static final FaestParameters faest_em_128s = new FaestParameters(
        "faest_em_128s", true,
        128, 11, 7, 103, 960,
        4, 0, 10, 160, 128, 832, 241,
        1, 16, 16, 32, 32, 3906);

    /**
     * FAEST-EM-128f: lambda=128, EM mode, fast-signing trade-off. Signature 5060 bytes.
     */
    public static final FaestParameters faest_em_128f = new FaestParameters(
        "faest_em_128f", true,
        128, 16, 8, 112, 960,
        4, 0, 10, 160, 128, 832, 241,
        1, 16, 16, 32, 32, 5060);

    /**
     * FAEST-EM-192s: lambda=192, EM mode, small-signature trade-off. Signature 9340 bytes.
     */
    public static final FaestParameters faest_em_192s = new FaestParameters(
        "faest_em_192s", true,
        192, 16, 8, 162, 1728,
        6, 0, 12, 288, 192, 1536, 433,
        1, 24, 24, 48, 48, 9340);

    /**
     * FAEST-EM-192f: lambda=192, EM mode, fast-signing trade-off. Signature 12380 bytes.
     */
    public static final FaestParameters faest_em_192f = new FaestParameters(
        "faest_em_192f", true,
        192, 24, 8, 176, 1728,
        6, 0, 12, 288, 192, 1536, 433,
        1, 24, 24, 48, 48, 12380);

    /**
     * FAEST-EM-256s: lambda=256, EM mode, small-signature trade-off. Signature 17984 bytes.
     */
    public static final FaestParameters faest_em_256s = new FaestParameters(
        "faest_em_256s", true,
        256, 22, 6, 218, 2688,
        8, 0, 14, 448, 256, 2432, 673,
        1, 32, 32, 64, 64, 17984);

    /**
     * FAEST-EM-256f: lambda=256, EM mode, fast-signing trade-off. Signature 23476 bytes.
     */
    public static final FaestParameters faest_em_256f = new FaestParameters(
        "faest_em_256f", true,
        256, 32, 8, 234, 2688,
        8, 0, 14, 448, 256, 2432, 673,
        1, 32, 32, 64, 64, 23476);

    // ----- Spec-mandated invariants -----

    /**
     * Max length of a witness, mirrors MAX_LAMBDA in instances.h.
     */
    public static final int MAX_LAMBDA = 256;
    /**
     * Max VOLE repetitions, mirrors MAX_TAU.
     */
    public static final int MAX_TAU = 32;
    /**
     * Universal-hash output width in bytes, mirrors UNIVERSAL_HASH_B.
     */
    public static final int UNIVERSAL_HASH_B = 2;
    /**
     * IV size in bytes for randomness expansion.
     */
    public static final int IV_SIZE = 16;

    // ----- Instance state -----

    private final String name;
    private final boolean em;

    // Main parameters (faest_param_t.lambda..ell)
    private final int lambda;
    private final int tau;
    private final int wGrind;
    private final int tOpen;
    private final int ell;

    // Derived (computed in the constructor below, mirroring instances.c CALC_*)
    private final int k;
    private final int tau0;
    private final int tau1;
    private final int L;

    // OWF parameters
    private final int Nst;
    private final int Ske;
    private final int R;
    private final int Senc;
    private final int Lke;
    private final int Lenc;
    private final int C;

    // Additional parameters
    private final int beta;
    private final int owfInputSize;
    private final int owfOutputSize;
    private final int pkSize;
    private final int skSize;
    private final int sigSize;

    private FaestParameters(String name, boolean em,
                            int lambda, int tau, int wGrind, int tOpen, int ell,
                            int Nst, int Ske, int R, int Senc, int Lke, int Lenc, int C,
                            int beta, int owfInputSize, int owfOutputSize,
                            int pkSize, int skSize, int sigSize)
    {
        this.name = name;
        this.em = em;
        this.lambda = lambda;
        this.tau = tau;
        this.wGrind = wGrind;
        this.tOpen = tOpen;
        this.ell = ell;

        // faest-ref instances.c:
        //   tau1 = (lambda - w_grind) % tau
        //   tau0 = tau - tau1
        //   k    = ((lambda - w_grind) / tau) + 1
        //   L    = tau1 * (1<<k) + tau0 * (1<<(k-1))
        this.tau1 = (lambda - wGrind) % tau;
        this.tau0 = tau - this.tau1;
        this.k = ((lambda - wGrind) / tau) + 1;
        this.L = this.tau1 * (1 << this.k) + this.tau0 * (1 << (this.k - 1));

        this.Nst = Nst;
        this.Ske = Ske;
        this.R = R;
        this.Senc = Senc;
        this.Lke = Lke;
        this.Lenc = Lenc;
        this.C = C;
        this.beta = beta;
        this.owfInputSize = owfInputSize;
        this.owfOutputSize = owfOutputSize;
        this.pkSize = pkSize;
        this.skSize = skSize;
        this.sigSize = sigSize;
    }

    /**
     * Return the parameter set whose {@link #getName()} matches, or null.
     */
    public static FaestParameters byName(String name)
    {
        FaestParameters[] all = {
            faest_128s, faest_128f, faest_192s, faest_192f, faest_256s, faest_256f,
            faest_em_128s, faest_em_128f, faest_em_192s, faest_em_192f, faest_em_256s, faest_em_256f
        };
        for (int i = 0; i != all.length; i++)
        {
            if (all[i].name.equals(name))
            {
                return all[i];
            }
        }
        return null;
    }

    public String getName()
    {
        return name;
    }

    public boolean isEm()
    {
        return em;
    }

    public int getLambda()
    {
        return lambda;
    }

    public int getLambdaBytes()
    {
        return lambda / 8;
    }

    public int getTau()
    {
        return tau;
    }

    public int getWGrind()
    {
        return wGrind;
    }

    public int getEll()
    {
        return ell;
    }

    public int getK()
    {
        return k;
    }

    public int getTau0()
    {
        return tau0;
    }

    public int getTau1()
    {
        return tau1;
    }

    public int getL()
    {
        return L;
    }

    public int getSke()
    {
        return Ske;
    }

    public int getOwfInputSize()
    {
        return owfInputSize;
    }

    public int getOwfOutputSize()
    {
        return owfOutputSize;
    }

    public int getPkSize()
    {
        return pkSize;
    }

    public int getSkSize()
    {
        return skSize;
    }

    public int getSigSize()
    {
        return sigSize;
    }

    // Spec-internal dimensions used only by the in-package constraint system.
    int getTOpen()
    {
        return tOpen;
    }

    int getNst()
    {
        return Nst;
    }

    int getR()
    {
        return R;
    }

    int getSenc()
    {
        return Senc;
    }

    int getLke()
    {
        return Lke;
    }

    int getLenc()
    {
        return Lenc;
    }

    int getC()
    {
        return C;
    }

    int getBeta()
    {
        return beta;
    }
}
