package org.bouncycastle.pqc.crypto.mldsa;

import java.security.SecureRandom;

public class MLDSAParameters
{
    public static final MLDSAParameters ml_dsa_44 = new MLDSAParameters("ml-dsa-44", 2);
    public static final MLDSAParameters ml_dsa_65 = new MLDSAParameters("ml-dsa-65", 3);
    public static final MLDSAParameters ml_dsa_87 = new MLDSAParameters("ml-dsa-87", 5);

    private final int k;
    private final String name;

    private MLDSAParameters(String name, int k)
    {
        this.name = name;
        this.k = k;
    }

    MLDSAEngine getEngine(SecureRandom random)
    {
        return new MLDSAEngine(k, random);
    }

    public String getName()
    {
        return name;
    }
}
