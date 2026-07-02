package org.bouncycastle.pqc.crypto.ntru;

import org.bouncycastle.util.Arrays;

/**
 * NTRU public key parameter class.
 */
public class NTRUPublicKeyParameters
    extends NTRUKeyParameters
{
    final byte[] publicKey;

    public NTRUPublicKeyParameters(NTRUParameters params, byte[] key)
    {
        super(false, params);

        if (key.length != params.getPublicKeyLength())
        {
            throw new IllegalArgumentException("'key' has invalid length");
        }

        this.publicKey = Arrays.clone(key);
    }

    /**
     * Get public key.
     *
     * @return a byte array containing public key
     */
    public byte[] getPublicKey()
    {
        return Arrays.clone(this.publicKey);
    }

    /**
     * Get the encoding of public key.
     *
     * @return a byte array containing public key encoding
     */
    public byte[] getEncoded()
    {
        return getPublicKey();
    }
}
