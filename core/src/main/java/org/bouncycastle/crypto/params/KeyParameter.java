package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;

/**
 * A key parameter to a cipher.
 */
public class KeyParameter
    implements CipherParameters
{
    private byte[]  key;

    /**
     * Construct a key parameter from key data.<br/>
     * The key data is copied by this constructor.
     *
     * @param key the key data.
     */
    public KeyParameter(
        byte[]  key)
    {
        this(key, 0, key.length);
    }

    /**
     * Construct a key parameter from key data.<br/>
     * The key data is copied by this constructor.
     *
     * @param key the array containing the key data.
     * @param keyOff the offset in the array where the key data begins.
     * @param keyLen the length of the key data.
     */
    public KeyParameter(
        byte[]  key,
        int     keyOff,
        int     keyLen)
    {
        this.key = new byte[keyLen];

        System.arraycopy(key, keyOff, this.key, 0, keyLen);
    }

    /**
     * Obtains a mutable reference to the key data in this parameter.
     */
    public byte[] getKey()
    {
        return key;
    }
}
