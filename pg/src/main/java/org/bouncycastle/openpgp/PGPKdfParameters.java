package org.bouncycastle.openpgp;

public class PGPKdfParameters
    implements PGPAlgorithmParameters
{
    private final int hashAlgorithm;
    private final int symmetricWrapAlgorithm;

    public PGPKdfParameters(int hashAlgorithm, int symmetricWrapAlgorithm)
    {
        this.hashAlgorithm = hashAlgorithm;
        this.symmetricWrapAlgorithm = symmetricWrapAlgorithm;
    }

    public int getSymmetricWrapAlgorithm()
    {
        return symmetricWrapAlgorithm;
    }

    public int getHashAlgorithm()
    {
        return hashAlgorithm;
    }
}
