package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.util.Arrays;

/**
 * Parameter spec for SM2 ID parameter
 */
public class SM2ParameterSpec
    implements AlgorithmParameterSpec
{
    private byte[] id;

    /**
     * Base constructor.
     *
     * @param id the ID string associated with this usage of SM2.
     */
    public SM2ParameterSpec(
        byte[] id)
    {
        if (id == null)
        {
            throw new NullPointerException("id string cannot be null");
        }

        this.id = Arrays.clone(id);
    }

    /**
     * Return the ID value.
     *
     * @return the ID string.
     */
    public byte[] getID()
    {
        return Arrays.clone(id);
    }
}
