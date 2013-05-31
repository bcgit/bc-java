package javax.crypto.spec;

import java.security.spec.AlgorithmParameterSpec;

/**
 * This class specifies an <i>initialization vector</i> (IV). IVs are used
 * by ciphers in feedback mode, e.g., DES in CBC mode.
 */
public class IvParameterSpec
    implements AlgorithmParameterSpec
{
    private byte[]  iv;

    /**
     * Uses the bytes in <code>iv</code> as the IV.
     *
     * @param iv the buffer with the IV
     */
    public IvParameterSpec(
        byte[]  iv)
    {
        if (iv == null)
        {
            throw new IllegalArgumentException("null iv passed");
        }

        this.iv = new byte[iv.length];

        System.arraycopy(iv, 0, this.iv, 0, iv.length);
    }

    /**
     * Uses the first <code>len</code> bytes in <code>iv</code>,
     * beginning at <code>offset</code> inclusive, as the IV.
     * <p>
     * The bytes that constitute the IV are those between
     * <code>iv[offset]</code> and <code>iv[offset+len-1]</code> inclusive.
     *
     * @param iv the buffer with the IV
     * @param offset the offset in <code>iv</code> where the IV starts
     * @param len the number of IV bytes
     */
    public IvParameterSpec(
        byte[]  iv,
        int     offset,
        int     len)
    {
        if (iv == null)
        {
            throw new IllegalArgumentException("Null iv passed");
        }

        if (offset < 0 || len < 0 || (iv.length - offset) < len)
        {
            throw new IllegalArgumentException("Bad offset/len");
        }

        this.iv = new byte[len];

        System.arraycopy(iv, offset, this.iv, 0, len);
    }

    /**
     * Returns the initialization vector (IV).
     *
     * @return the initialization vector (IV)
     */
    public byte[] getIV()
    {
        byte[]  tmp = new byte[iv.length];

        System.arraycopy(iv, 0, tmp, 0, iv.length);
        return tmp;
    }
}
