package javax.crypto.spec;

import java.security.InvalidKeyException;
import java.security.spec.KeySpec;

/**
 * This class specifies a DES key.
 */
public class DESKeySpec
    implements KeySpec
{
    public static final int DES_KEY_LEN = 8;

    private byte[]  keyBytes = new byte[DES_KEY_LEN];

    /**
     * Uses the first 8 bytes in <code>key</code> as the key material for the DES key.
     * <p>
     * The bytes that constitute the DES key are those between
     * <code>key[0]</code> and <code>key[7]</code> inclusive.
     * 
     * @param key - the buffer with the DES key material.
     * @exception InvalidKeyException - if the given key material is shorter than 8 bytes.
     */
    public DESKeySpec(
        byte[]  key)
    throws InvalidKeyException
    {
        if (key.length < DES_KEY_LEN)
        {
            throw new InvalidKeyException("DES key material too short in construction");
        }

        System.arraycopy(key, 0, keyBytes, 0, keyBytes.length);
    }

    /**
     * Uses the first 8 bytes in <code>key</code>, beginning at
     * <code>offset</code> inclusive, as the key material for the DES key.
     * <p>
     * The bytes that constitute the DES key are those between
     * <code>key[offset]</code> and <code>key[offset+7]</code> inclusive.
     *
     * @param key the buffer with the DES key material.
     * @param offset the offset in <code>key</code>, where the DES key material starts.
     * @exception InvalidKeyException if the given key material, starting at
     * <code>offset</code> inclusive, is shorter than 8 bytes.
     */
    public DESKeySpec(
        byte[]  key,
        int     offset)
    throws InvalidKeyException
    {
        if ((key.length - offset) < DES_KEY_LEN)
        {
            throw new InvalidKeyException("DES key material too short in construction");
        }

        System.arraycopy(key, offset, keyBytes, 0, keyBytes.length);
    }

    /**
     * Returns the DES key material.
     *
     * @return the DES key material.
     */
    public byte[] getKey()
    {
        byte[]  tmp = new byte[DES_KEY_LEN];

        System.arraycopy(keyBytes, 0, tmp, 0, tmp.length);

        return tmp;
    }

    /**
     * Checks if the given DES key material, starting at <code>offset</code>
     * inclusive, is parity-adjusted.
     *
     * @param key the buffer with the DES key material.
     * @param offset the offset in <code>key</code>, where the DES key material starts.
     * @returns true if the given DES key material is parity-adjusted, false otherwise.
     * @exception InvalidKeyException if the given key material, starting at <code>offset</code>
     * inclusive, is shorter than 8 bytes.
     */
    public static boolean isParityAdjusted(
        byte[]  key,
        int     offset)
    throws InvalidKeyException
    {
        if ((key.length - offset) < DES_KEY_LEN)
        {
            throw new InvalidKeyException("key material too short in DESKeySpec.isParityAdjusted");
        }

        for (int i = 0; i < DES_KEY_LEN; i++)
        {
            byte    keyByte = key[i + offset];
            int     count = 0;

            keyByte = (byte)((keyByte & 0xff) >> 1);
            
            while (keyByte != 0)
            {
                /*
                 * we increment for every "on" bit
                 */
                if ((keyByte & 0x01) != 0)
                {
                    count++;
                }

                keyByte = (byte)((keyByte & 0xff) >> 1);
            }

            if ((count & 1) == 1)
            {
                if ((key[i + offset] & 1) == 1)
                {
                    return false;
                }
            }
            else if ((key[i + offset] & 1) != 1)
            {
                return false;
            }
        }

        return true;
    }

    /*
     * Table of weak and semi-weak keys taken from Schneier pp281
     */
    static private final int N_DES_WEAK_KEYS = 16;

    static private byte[] DES_weak_keys =
    {
        /* weak keys */
        (byte)0x01,(byte)0x01,(byte)0x01,(byte)0x01, (byte)0x01,(byte)0x01,(byte)0x01,(byte)0x01,
        (byte)0x1f,(byte)0x1f,(byte)0x1f,(byte)0x1f, (byte)0x0e,(byte)0x0e,(byte)0x0e,(byte)0x0e,
        (byte)0xe0,(byte)0xe0,(byte)0xe0,(byte)0xe0, (byte)0xf1,(byte)0xf1,(byte)0xf1,(byte)0xf1,
        (byte)0xfe,(byte)0xfe,(byte)0xfe,(byte)0xfe, (byte)0xfe,(byte)0xfe,(byte)0xfe,(byte)0xfe,

        /* semi-weak keys */
        (byte)0x01,(byte)0xfe,(byte)0x01,(byte)0xfe, (byte)0x01,(byte)0xfe,(byte)0x01,(byte)0xfe,
        (byte)0x1f,(byte)0xe0,(byte)0x1f,(byte)0xe0, (byte)0x0e,(byte)0xf1,(byte)0x0e,(byte)0xf1,
        (byte)0x01,(byte)0xe0,(byte)0x01,(byte)0xe0, (byte)0x01,(byte)0xf1,(byte)0x01,(byte)0xf1,
        (byte)0x1f,(byte)0xfe,(byte)0x1f,(byte)0xfe, (byte)0x0e,(byte)0xfe,(byte)0x0e,(byte)0xfe,
        (byte)0x01,(byte)0x1f,(byte)0x01,(byte)0x1f, (byte)0x01,(byte)0x0e,(byte)0x01,(byte)0x0e,
        (byte)0xe0,(byte)0xfe,(byte)0xe0,(byte)0xfe, (byte)0xf1,(byte)0xfe,(byte)0xf1,(byte)0xfe,
        (byte)0xfe,(byte)0x01,(byte)0xfe,(byte)0x01, (byte)0xfe,(byte)0x01,(byte)0xfe,(byte)0x01,
        (byte)0xe0,(byte)0x1f,(byte)0xe0,(byte)0x1f, (byte)0xf1,(byte)0x0e,(byte)0xf1,(byte)0x0e,
        (byte)0xe0,(byte)0x01,(byte)0xe0,(byte)0x01, (byte)0xf1,(byte)0x01,(byte)0xf1,(byte)0x01,
        (byte)0xfe,(byte)0x1f,(byte)0xfe,(byte)0x1f, (byte)0xfe,(byte)0x0e,(byte)0xfe,(byte)0x0e,
        (byte)0x1f,(byte)0x01,(byte)0x1f,(byte)0x01, (byte)0x0e,(byte)0x01,(byte)0x0e,(byte)0x01,
        (byte)0xfe,(byte)0xe0,(byte)0xfe,(byte)0xe0, (byte)0xfe,(byte)0xf1,(byte)0xfe,(byte)0xf1
    };

    /**
     * Checks if the given DES key material is weak or semi-weak.
     *
     * @param key the buffer with the DES key material.
     * @param offset the offset in <code>key</code>, where the DES key
     * material starts.
     * @return true if the given DES key material is weak or semi-weak, false otherwise.
     * @exception InvalidKeyException if the given key material, starting at <code>offset</code>
     * inclusive, is shorter than 8 bytes.
     */
    public static boolean isWeak(
        byte[]  key,
        int     offset)
    throws InvalidKeyException
    {
        if (key.length - offset < DES_KEY_LEN)
        {
            throw new InvalidKeyException("key material too short in DESKeySpec.isWeak");
        }

        nextkey: for (int i = 0; i < N_DES_WEAK_KEYS; i++)
        {
            for (int j = 0; j < DES_KEY_LEN; j++)
            {
                if (key[j + offset] != DES_weak_keys[i * DES_KEY_LEN + j])
                {
                    continue nextkey;
                }
            }

            return true;
        }
        return false;
    }
}
