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

    int getMode()
    {
        return mode;
    }

    SmaugTEngine getEngine()
    {
        return engine;
    }
}
