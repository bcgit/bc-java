package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.util.Arrays;

/**
 * Parameter spec carrying an SM9 identity, supplied to a {@code SM3withSM9}
 * {@link java.security.Signature} before verification (the signer's identity is
 * needed to derive its public key). For encryption it identifies the recipient.
 */
public class SM9ParameterSpec
    implements AlgorithmParameterSpec
{
    private final byte[] id;

    public SM9ParameterSpec(byte[] id)
    {
        if (id == null)
        {
            throw new NullPointerException("id cannot be null");
        }
        this.id = Arrays.clone(id);
    }

    public byte[] getId()
    {
        return Arrays.clone(id);
    }
}
