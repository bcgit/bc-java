package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.util.Arrays;

public class UserKeyingMaterialSpec
    implements AlgorithmParameterSpec
{
    private final byte[] userKeyingMaterial;
    private final byte[] salt;

    /**
     * Base constructor.
     *
     * @param userKeyingMaterial the bytes to be mixed in to the key agreement's KDF.
     */
    public UserKeyingMaterialSpec(byte[] userKeyingMaterial)
    {
        this(userKeyingMaterial, null);
    }

    /**
     * Base constructor.
     *
     * @param userKeyingMaterial the bytes to be mixed in to the key agreement's KDF.
     * @param salt the salt to use with the underlying KDF.
     */
    public UserKeyingMaterialSpec(byte[] userKeyingMaterial, byte[] salt)
    {
        this.userKeyingMaterial = Arrays.clone(userKeyingMaterial);
        this.salt = Arrays.clone(salt);
    }

    /**
     * Return a copy of the key material in this object.
     *
     * @return the user keying material.
     */
    public byte[] getUserKeyingMaterial()
    {
        return Arrays.clone(userKeyingMaterial);
    }

    /**
     * Return a copy of the salt in this object.
     *
     * @return the KDF salt.
     */
    public byte[] getSalt()
    {
        return Arrays.clone(salt);
    }
}
