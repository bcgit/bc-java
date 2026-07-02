package org.bouncycastle.pqc.crypto.ntru;

import org.bouncycastle.util.Arrays;

/**
 * NTRU private key parameter class.
 */
public class NTRUPrivateKeyParameters
    extends NTRUKeyParameters
{
    final byte[] privateKey;

    public NTRUPrivateKeyParameters(NTRUParameters params, byte[] key)
    {
        super(true, params);

        if (key.length != params.getPrivateKeyLength())
        {
            throw new IllegalArgumentException("'key' has invalid length");
        }

        this.privateKey = Arrays.clone(key);
    }

    /**
     * Get private key.
     *
     * @return a byte array containing private key
     */
    public byte[] getPrivateKey()
    {
        return Arrays.clone(this.privateKey);
    }

    /**
     * Get the encoding of the private key.
     *
     * @return a byte array containing private key
     */
    public byte[] getEncoded()
    {
        return getPrivateKey();
    }
}
