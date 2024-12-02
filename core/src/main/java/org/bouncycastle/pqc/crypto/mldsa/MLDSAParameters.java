package org.bouncycastle.pqc.crypto.mldsa;

import java.security.SecureRandom;

public class MLDSAParameters
{
    public static final int TYPE_PURE = 0;
    public static final int TYPE_SHA2_512 = 1;

    public static final MLDSAParameters ml_dsa_44 = new MLDSAParameters("ml-dsa-44", 2, TYPE_PURE);
    public static final MLDSAParameters ml_dsa_65 = new MLDSAParameters("ml-dsa-65", 3, TYPE_PURE);
    public static final MLDSAParameters ml_dsa_87 = new MLDSAParameters("ml-dsa-87", 5, TYPE_PURE);

    public static final MLDSAParameters ml_dsa_44_with_sha512 = new MLDSAParameters("ml-dsa-44-with-sha512", 2, TYPE_SHA2_512);
    public static final MLDSAParameters ml_dsa_65_with_sha512 = new MLDSAParameters("ml-dsa-65-with-sha512", 3, TYPE_SHA2_512);
    public static final MLDSAParameters ml_dsa_87_with_sha512 = new MLDSAParameters("ml-dsa-87-with-sha512", 5, TYPE_SHA2_512);

    private final int k;
    private final String name;
    private final int preHashDigest;

    private MLDSAParameters(String name, int k, int preHashDigest)
    {
        this.name = name;
        this.k = k;
        this.preHashDigest = preHashDigest;
    }

    public boolean isPreHash()
    {
        return preHashDigest != TYPE_PURE;
    }

    public int getType()
    {
        return preHashDigest;
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
