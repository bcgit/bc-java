package org.bouncycastle.jcajce.spec;

import java.security.spec.KeySpec;

import org.bouncycastle.util.Arrays;

/**
 * PublicKeySpec for ML-DSA.
 */
public class MLKEMPublicKeySpec
    implements KeySpec
{
    private final MLKEMParameterSpec params;
    private final byte[] publicData;

    /**
     * Base constructor.
     *
     * @param params the parameters to use with the passed in encoding.
     * @param publicData the long form encoding of the public key.
     */
    public MLKEMPublicKeySpec(MLKEMParameterSpec params, byte[] publicData)
    {
        this.params = params;
        this.publicData = Arrays.clone(publicData);
    }

    public MLKEMParameterSpec getParameterSpec()
    {
        return params;
    }

    public byte[] getPublicData()
    {
        return Arrays.clone(publicData);
    }
}
