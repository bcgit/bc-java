package org.bouncycastle.pqc.crypto.crystals.kyber;

import org.bouncycastle.pqc.crypto.KEMParameters;

public class KyberParameters
    implements KEMParameters
{
    public static final KyberParameters kyber512 = new KyberParameters("kyber512", 2, 256, false);
    public static final KyberParameters kyber768 = new KyberParameters("kyber768", 3, 256, false);
    public static final KyberParameters kyber1024 = new KyberParameters("kyber1024", 4, 256, false);

    private final String name;
    private final int k;
    private final int sessionKeySize;

    /**
     * @deprecated
     * obsolete to be removed
     */
    @Deprecated
    private final boolean usingAes;

    private KyberParameters(String name, int k, int sessionKeySize, boolean usingAes)
    {
        this.name = name;
        this.k = k;
        this.sessionKeySize = sessionKeySize;
        this.usingAes = usingAes;
    }

    public String getName()
    {
        return name;
    }

    KyberEngine getEngine()
    {
        return new KyberEngine(k, usingAes);
    }

    public int getSessionKeySize()
    {
        return sessionKeySize;
    }
}
