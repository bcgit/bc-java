package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.KEMParameters;
import org.bouncycastle.crypto.kems.mlkem.MLKEMEngine;

public class MLKEMParameters
    implements KEMParameters
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

    public int getSessionKeySize()
    {
        return 256;
    }
}
