package org.bouncycastle.pqc.crypto.uov;

import org.bouncycastle.util.Arrays;

public class UOVPublicKeyParameters
    extends UOVKeyParameters
{
    private final byte[] encoded;

    public UOVPublicKeyParameters(UOVParameters params, byte[] encoded)
    {
        super(false, params);
        if (encoded == null)
        {
            throw new NullPointerException("encoded cannot be null");
        }
        if (encoded.length != params.getPublicKeyBytes())
        {
            throw new IllegalArgumentException("public key encoding wrong length for " + params.getName());
        }
        this.encoded = Arrays.clone(encoded);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(encoded);
    }

    /**
     * Package-private read-only view of the encoded key. Returns the
     * internal byte[] without cloning so the engine can avoid allocating
     * multi-MB defensive copies per verify call. Callers MUST treat the
     * returned array as read-only; never mutate, never expose.
     */
    byte[] borrowEncoded()
    {
        return encoded;
    }
}
