package javax.crypto.spec;

import java.security.InvalidKeyException;
import java.security.spec.KeySpec;

/**
 * This class specifies a DES-EDE ("triple-DES") key.
 */
public class DESedeKeySpec
    implements KeySpec
{
    public static final int DES_EDE_KEY_LEN = 24;

    private byte[]  keyBytes = new byte[DES_EDE_KEY_LEN];

    /**
     * Uses the first 24 bytes in <code>key</code> as the DES-EDE key.
     * <p>
     * The bytes that constitute the DES-EDE key are those between
     * <code>key[0]</code> and <code>key[23]</code> inclusive
     *
     * @param key the buffer with the DES-EDE key material.
     * @exception InvalidKeyException if the given key material is shorter
     * than 24 bytes.
     */
    public DESedeKeySpec(
        byte[]  key)
        throws InvalidKeyException
    {
        if (key.length < DES_EDE_KEY_LEN)
        {
            throw new InvalidKeyException("DESede key material too short in construction");
        }

        System.arraycopy(key, 0, keyBytes, 0, keyBytes.length);
    }

    /**
     * Uses the first 24 bytes in <code>key</code>, beginning at
     * <code>offset</code> inclusive, as the DES-EDE key.
     * <p>
     * The bytes that constitute the DES-EDE key are those between
     * <code>key[offset]</code> and <code>key[offset+23]</code> inclusive.
     * @param key the buffer with the DES-EDE key material.
     * @param offset the offset in <code>key</code>, where the DES-EDE key
     * material starts.
     * @exception InvalidKeyException if the given key material, starting at
     * <code>offset</code> inclusive, is shorter than 24 bytes
     */
    public DESedeKeySpec(
        byte[]  key,
        int     offset)
    throws InvalidKeyException
    {
        if ((key.length - offset) < DES_EDE_KEY_LEN)
        {
            throw new InvalidKeyException("DESede key material too short in construction");
        }

        System.arraycopy(key, 0, keyBytes, 0, keyBytes.length);
    }

    /**
     * Returns the DES-EDE key.
     *
     * @return the DES-EDE key
     */
    public byte[] getKey()
    {
        byte[]  tmp = new byte[DES_EDE_KEY_LEN];

        System.arraycopy(keyBytes, 0, tmp, 0, tmp.length);

        return tmp;
    }

    /**
     * Checks if the given DES-EDE key, starting at <code>offset</code>
     * inclusive, is parity-adjusted.
     *
     * @return true if the given DES-EDE key is parity-adjusted, false
     * otherwise
     * @exception InvalidKeyException if the given key material, starting at
     * <code>offset</code> inclusive, is shorter than 24 bytes
     */
    public static boolean isParityAdjusted(
        byte[]  key,
        int     offset)
    throws InvalidKeyException
    {
        if ((key.length - offset) < DES_EDE_KEY_LEN)
        {
            throw new InvalidKeyException("key material too short in DESedeKeySpec.isParityAdjusted");
        }

        return (DESKeySpec.isParityAdjusted(key, offset)
                && DESKeySpec.isParityAdjusted(key, offset + 8)
                && DESKeySpec.isParityAdjusted(key, offset + 16));
    }
}
