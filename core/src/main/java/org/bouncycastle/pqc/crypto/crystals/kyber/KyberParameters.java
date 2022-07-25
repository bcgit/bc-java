package org.bouncycastle.pqc.crypto.crystals.kyber;

public class KyberParameters
{
    public static final KyberParameters kyber512 = new KyberParameters(2);
    public static final KyberParameters kyber768 = new KyberParameters(3);
    public static final KyberParameters kyber1024 = new KyberParameters(4);

    private final int k;

    private KyberParameters(int k)
    {
        this.k = k;
    }

    KyberEngine getEngine()
    {

        return new KyberEngine(k);
    }

}
