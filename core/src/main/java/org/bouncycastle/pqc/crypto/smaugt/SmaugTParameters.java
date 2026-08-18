package org.bouncycastle.pqc.crypto.smaugt;

import org.bouncycastle.pqc.crypto.KEMParameters;

/**
 * Parameter set for the SMAUG-T post-quantum key encapsulation mechanism
 * (Module-Lizard / MLWE+MLWR, SMAUG-T v1.2.0 reference specification). The
 * four submission variants are exposed as the {@link #smaugt_mode1},
 * {@link #smaugt_mode3} and {@link #smaugt_mode5} constants (NIST security
 * categories 1/3/5) and {@link #smaugt_modet} (TiMER, the bandwidth-optimised
 * variant using the D2 encoding).
 */
public class SmaugTParameters
    implements KEMParameters
{
    static final int MODE1 = 0;
    static final int MODE3 = 1;
    static final int MODE5 = 2;
    static final int MODET = 3;

    public static final SmaugTParameters smaugt_mode1 = new SmaugTParameters("smaugt-mode1", MODE1, 256);
    public static final SmaugTParameters smaugt_mode3 = new SmaugTParameters("smaugt-mode3", MODE3, 256);
    public static final SmaugTParameters smaugt_mode5 = new SmaugTParameters("smaugt-mode5", MODE5, 256);
    public static final SmaugTParameters smaugt_modet = new SmaugTParameters("smaugt-modet", MODET, 256);

    private final String name;
    private final int mode;
    private final int defaultKeySize;
    private final SmaugTEngine engine;

    private SmaugTParameters(String name, int mode, int defaultKeySize)
    {
        this.name = name;
        this.mode = mode;
        this.defaultKeySize = defaultKeySize;
        this.engine = new SmaugTEngine(mode);
    }

    public String getName()
    {
        return name;
    }

    public int getSessionKeySize()
    {
        return defaultKeySize;
    }

    /**
     * Return the size in bytes of an encapsulation produced for this parameter set. The engine that
     * knows it is package private, so this is the only way the encapsulating side - which holds a
     * public key and no extractor - can obtain it.
     */
    public int getEncapsulationLength()
    {
        return engine.getCipherTextBytes();
    }

    int getMode()
    {
        return mode;
    }

    /**
     * Return the engine for this parameter set. One instance is shared by every caller for the life
     * of the JVM, so SmaugTEngine must stay immutable - see its class javadoc.
     */
    SmaugTEngine getEngine()
    {
        return engine;
    }
}
