package org.bouncycastle.jcajce.spec;

import org.bouncycastle.jcajce.spec.ScryptKeySpec;

import java.security.spec.AlgorithmParameterSpec;

public class ScryptParameterSpec
    extends ScryptKeySpec
    implements AlgorithmParameterSpec
{
    public ScryptParameterSpec(char[] password, byte[] salt, int costParameter, int blockSize, int parallelizationParameter, int keySize)
    {
        super(password, salt, costParameter, blockSize, parallelizationParameter, keySize);
    }
}
