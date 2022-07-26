package org.bouncycastle.pqc.crypto.crystals.kyber;

public class KyberParameters
{
    public static final KyberParameters kyber512 = new KyberParameters("kyber512", 2, 128);
    public static final KyberParameters kyber768 = new KyberParameters("kyber768", 3, 192);
    public static final KyberParameters kyber1024 = new KyberParameters("kyber1024", 4, 256);

    private final String name;
    private final int k;
    private final int sessionKeySize;

    private KyberParameters(String name, int k, int sessionKeySize)
    {
        this.name = name;
        this.k = k;
        this.sessionKeySize = sessionKeySize;
    }

    public String getName()
    {
        return name;
    }

    KyberEngine getEngine()
    {
        return new KyberEngine(k);
    }

    public int getSessionKeySize()
    {
        return sessionKeySize;
    }
}
