package org.bouncycastle.crypto.params;

public class MLDSAParameters
    implements PQCParameters
{
    public static final int TYPE_PURE = 0;
    public static final int TYPE_SHA2_512 = 1;

    /**
     * ML-DSA-44. NIST security category 2 provided the random bit generator used for key
     * generation and signing has at least 192 bits of security, category 1 otherwise (NIST IR
     * 8547, Table 3, note 2).
     */
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

    public int getK()
    {
        return k;
    }
   
    public String getName()
    {
        return name;
    }

    /**
     * Return the NIST security category of this parameter set: 2 for ML-DSA-44, 3 for ML-DSA-65
     * and 5 for ML-DSA-87 (NIST IR 8547, Table 3). Note that NIST reduces ML-DSA-44 to category 1
     * when the key or signature was produced with an approved RBG of less than 192 bits of
     * security (NIST IR 8547, Table 3, note 2).
     */
    public int getSecurityCategory()
    {
        switch (k)
        {
        case 2:
            return 2;
        case 3:
            return 3;
        default:
            return 5;
        }
    }

    /**
     * Return the classical security strength of this parameter set: 128 bits for ML-DSA-44, 192
     * for ML-DSA-65 and 256 for ML-DSA-87 (NIST IR 8547, Table 3).
     */
    public int getClassicalSecurityStrength()
    {
        switch (k)
        {
        case 2:
            return 128;
        case 3:
            return 192;
        default:
            return 256;
        }
    }
}
