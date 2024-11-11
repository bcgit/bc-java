package org.bouncycastle.jcajce.spec;

import java.security.spec.KeySpec;

import org.bouncycastle.util.Arrays;

/**
 * PublicKeySpec for ML-DSA.
 */
public class MLDSAPublicKeySpec
    implements KeySpec
{
    private final MLDSAParameterSpec params;
    private final byte[] publicData;

    /**
     * Base constructor.
     *
     * @param params the parameters to use with the passed in encoding.
     * @param publicData the long form encoding of the public key.
     */
    public MLDSAPublicKeySpec(MLDSAParameterSpec params, byte[] publicData)
    {
        this.params = params;
        this.publicData = Arrays.clone(publicData);
    }

    public MLDSAParameterSpec getParameterSpec()
    {
        return params;
    }

    public byte[] getPublicData()
    {
        return Arrays.clone(publicData);
    }
}
