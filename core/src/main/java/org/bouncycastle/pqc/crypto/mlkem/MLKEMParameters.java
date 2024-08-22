package org.bouncycastle.pqc.crypto.mlkem;

import org.bouncycastle.pqc.crypto.KEMParameters;

public class MLKEMParameters
    implements KEMParameters
{
    public static final MLKEMParameters kyber512 = new MLKEMParameters("kyber512", 2, 256, false);
    public static final MLKEMParameters kyber768 = new MLKEMParameters("kyber768", 3, 256, false);
    public static final MLKEMParameters kyber1024 = new MLKEMParameters("kyber1024", 4, 256, false);

    private final String name;
    private final int k;
    private final int sessionKeySize;

    /**
     * @deprecated
     * obsolete to be removed
     */
    private final boolean usingAes;

    private MLKEMParameters(String name, int k, int sessionKeySize, boolean usingAes)
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

    public MLKEMEngine getEngine()
    {
        return new MLKEMEngine(k, usingAes);
    }

    public int getSessionKeySize()
    {
        return sessionKeySize;
    }
}
