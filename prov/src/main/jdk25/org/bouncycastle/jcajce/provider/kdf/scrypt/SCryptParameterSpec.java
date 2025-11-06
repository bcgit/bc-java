package org.bouncycastle.jcajce.provider.kdf.scrypt;

import org.bouncycastle.jcajce.spec.ScryptKeySpec;

import java.security.spec.AlgorithmParameterSpec;

public class SCryptParameterSpec
    extends ScryptKeySpec
    implements AlgorithmParameterSpec
{
    public SCryptParameterSpec(char[] password, byte[] salt, int costParameter, int blockSize, int parallelizationParameter, int keySize)
    {
        super(password, salt, costParameter, blockSize, parallelizationParameter, keySize);
    }
}
