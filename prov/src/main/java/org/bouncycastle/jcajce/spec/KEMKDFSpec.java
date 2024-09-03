package org.bouncycastle.jcajce.spec;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.Arrays;

public class KEMKDFSpec
{
    private final String keyAlgorithmName;
    private final int keySizeInBits;
    private final AlgorithmIdentifier kdfAlgorithm;
    private final byte[] otherInfo;

    protected KEMKDFSpec(AlgorithmIdentifier kdfAlgorithm, byte[] otherInfo, String keyAlgorithmName, int keySizeInBits)
    {
        this.keyAlgorithmName = keyAlgorithmName;
        this.keySizeInBits = keySizeInBits;
        this.kdfAlgorithm = kdfAlgorithm;
        this.otherInfo = otherInfo;
    }

    public String getKeyAlgorithmName()
    {
        return keyAlgorithmName;
    }

    public int getKeySize()
    {
        return keySizeInBits;
    }

    public AlgorithmIdentifier getKdfAlgorithm()
    {
        return kdfAlgorithm;
    }

    public byte[] getOtherInfo()
    {
        return Arrays.clone(otherInfo);
    }
}
