package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.KEMParameters;
import org.bouncycastle.crypto.kems.mlkem.MLKEMEngine;

public class MLKEMParameters
    implements KEMParameters, PQCParameters
{
    public static final MLKEMParameters ml_kem_512 = new MLKEMParameters("ML-KEM-512", 2);
    public static final MLKEMParameters ml_kem_768 = new MLKEMParameters("ML-KEM-768", 3);
    public static final MLKEMParameters ml_kem_1024 = new MLKEMParameters("ML-KEM-1024", 4);

    private final String name;
    private final int k;

    private MLKEMParameters(String name, int k)
    {
        if (name == null)
        {
            throw new NullPointerException("'name' cannot be null");
        }

        this.name = name;
        this.k = k;
    }

    public int getK()
    {
        return k;
    }

    public int getEncapsulationLength()
    {
        return MLKEMEngine.getInstance(this).getCipherTextBytes();
    }

    public String getName()
    {
        return name;
    }

    /**
     * Return the NIST security category of this parameter set: 1 for ML-KEM-512, 3 for
     * ML-KEM-768 and 5 for ML-KEM-1024 (NIST IR 8547, Table 5).
     */
    public int getSecurityCategory()
    {
        switch (k)
        {
        case 2:
            return 1;
        case 3:
            return 3;
        default:
            return 5;
        }
    }

    /**
     * Return the classical security strength of this parameter set: 128 bits for ML-KEM-512,
     * 192 for ML-KEM-768 and 256 for ML-KEM-1024 (NIST IR 8547, Table 5).
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

    public int getSessionKeySize()
    {
        return 256;
    }
}
