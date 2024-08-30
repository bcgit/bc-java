package org.bouncycastle.pqc.crypto.mldsa;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;

import java.security.SecureRandom;

public class MLDSAParameters
{
    public static final MLDSAParameters ml_dsa_44 = new MLDSAParameters("ml-dsa-44", 2, null);
    public static final MLDSAParameters ml_dsa_65 = new MLDSAParameters("ml-dsa-65", 3, null);
    public static final MLDSAParameters ml_dsa_87 = new MLDSAParameters("ml-dsa-87", 5, null);

    public static final MLDSAParameters hash_ml_dsa_44 = new MLDSAParameters("hash-ml-dsa-44-with-sha512", 2, new SHA512Digest());
    public static final MLDSAParameters hash_ml_dsa_65 = new MLDSAParameters("hash-ml-dsa-65-with-sha512", 3, new SHA512Digest());
    public static final MLDSAParameters hash_ml_dsa_87 = new MLDSAParameters("hash-ml-dsa-87-with-sha512", 5, new SHA512Digest());

    private final int k;
    private final String name;
    private final Digest preHashDigest;

    private MLDSAParameters(String name, int k, Digest preHashDigest)
    {
        this.name = name;
        this.k = k;
        this.preHashDigest = preHashDigest;
    }

    public Digest getDigest()
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
