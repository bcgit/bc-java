package org.bouncycastle.pqc.crypto.mldsa;

import java.security.SecureRandom;

public class MLDSAParameters
{
    public static final MLDSAParameters ml_dsa_44 = new MLDSAParameters("ml-dsa-44", 2, false);
    public static final MLDSAParameters ml_dsa_65 = new MLDSAParameters("ml-dsa-65", 3, false);
    public static final MLDSAParameters ml_dsa_87 = new MLDSAParameters("ml-dsa-87", 5, false);

    public static final MLDSAParameters hash_ml_dsa_44 = new MLDSAParameters("hash-ml-dsa-44", 2, true);
    public static final MLDSAParameters hash_ml_dsa_65 = new MLDSAParameters("hash-ml-dsa-65", 3, true);
    public static final MLDSAParameters hash_ml_dsa_87 = new MLDSAParameters("hash-ml-dsa-87", 5, true);

    private final int k;
    private final String name;
    private final boolean isPreHash;

    private MLDSAParameters(String name, int k, boolean isPreHash)
    {
        this.name = name;
        this.k = k;
        this.isPreHash = isPreHash;
    }

    MLDSAEngine getEngine(SecureRandom random)
    {
        return new MLDSAEngine(k, random, isPreHash);
    }

    public String getName()
    {
        return name;
    }
}
