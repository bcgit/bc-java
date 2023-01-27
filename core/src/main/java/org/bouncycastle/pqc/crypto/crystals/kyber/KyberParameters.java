package org.bouncycastle.pqc.crypto.crystals.kyber;

import org.bouncycastle.pqc.crypto.KEMParameters;

public class KyberParameters
    implements KEMParameters
{
    public static final KyberParameters kyber512 = new KyberParameters("kyber512", 2, 128, false);
    public static final KyberParameters kyber768 = new KyberParameters("kyber768", 3, 192, false);
    public static final KyberParameters kyber1024 = new KyberParameters("kyber1024", 4, 256, false);
    public static final KyberParameters kyber512_aes = new KyberParameters("kyber512-aes", 2, 128, true);
    public static final KyberParameters kyber768_aes = new KyberParameters("kyber768-aes", 3, 192, true);
    public static final KyberParameters kyber1024_aes = new KyberParameters("kyber1024-aes", 4, 256, true);

    private final String name;
    private final int k;
    private final int sessionKeySize;
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
