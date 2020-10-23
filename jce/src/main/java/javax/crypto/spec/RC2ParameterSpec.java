package javax.crypto.spec;

import java.security.spec.AlgorithmParameterSpec;

/**
 * This class specifies the parameters used with the
 * <a href="https://www.rsa.com/rsalabs/newfaq/q75.html"><i>RC2</i></a>
 * algorithm.
 * <p>
 * The parameters consist of an effective key size and optionally
 * an 8-byte initialization vector (IV) (only in feedback mode).
 * <p>
 * This class can be used to initialize a <code>Cipher</code> object that
 * implements the <i>RC2</i> algorithm.
 */
public class RC2ParameterSpec
    implements AlgorithmParameterSpec
{
    private int     effectiveKeyBits;
    private byte[]  iv = new byte[8];

    /**
     * Constructs a parameter set for RC2 from the given effective key size
     * (in bits).
     *
     * @param effectiveKeyBits the effective key size in bits.
     */
    public RC2ParameterSpec(
        int effectiveKeyBits)
    {
        this.effectiveKeyBits = effectiveKeyBits;
    }

    /**
     * Constructs a parameter set for RC2 from the given effective key size
     * (in bits) and an 8-byte IV.
     * <p>
     * The bytes that constitute the IV are those between
     * <code>iv[0]</code> and <code>iv[7]</code> inclusive.
     *
     * @param effectiveKeyBits the effective key size in bits.
     * @param iv the buffer with the 8-byte IV.
     */
    public RC2ParameterSpec(
        int     effectiveKeyBits,
        byte[]  iv)
    {
        this(effectiveKeyBits, iv, 0);
    }

    /**
     * Constructs a parameter set for RC2 from the given effective key size
     *  (in bits) and IV.
     * <p>
     * The IV is taken from <code>iv</code>, starting at
     * <code>offset</code> inclusive.
     * The bytes that constitute the IV are those between
     * <code>iv[offset]</code> and <code>iv[offset+7]</code> inclusive.
     *
     * @param effectiveKeyBits the effective key size in bits.
     * @param iv the buffer with the IV.
     * @param offset the offset in <code>iv</code> where the 8-byte IV starts.
     */
    public RC2ParameterSpec(
        int     effectiveKeyBits,
        byte[]  iv,
        int     offset)
    {
        this.effectiveKeyBits = effectiveKeyBits;

        this.iv = new byte[8];
        System.arraycopy(iv, offset, this.iv, 0, this.iv.length);
    }

    /**
     * Returns the effective key size in bits.
     *
     * @return the effective key size in bits.
     */
    public int getEffectiveKeyBits()
    {
        return effectiveKeyBits;
    }

    /**
     * Returns the IV or null if this parameter set does not contain an IV.
     *
     * @return the IV or null if this parameter set does not contain an IV.
     */
    public byte[] getIV()
    {
        if (iv == null)
        {
            return null;
        }

        byte[]  tmp = new byte[iv.length];

        System.arraycopy(iv, 0, tmp, 0, tmp.length);

        return tmp;
    }

    /**
     * Tests for equality between the specified object and this
     * object. Two RC2ParameterSpec objects are considered equal if their 
     * effective key sizes and IVs are equal.
     * (Two IV references are considered equal if both are <tt>null</tt>.)
     * 
     * @param obj the object to test for equality with this object.
     * @return true if the objects are considered equal, false otherwise.
     * @override equals in class java.lang.Object
     */
    public boolean equals(
        Object  obj)
    {
        if ((obj == null) || !(obj instanceof RC2ParameterSpec))
        {
            return false;
        }

        RC2ParameterSpec spec = (RC2ParameterSpec)obj;

        if (this.effectiveKeyBits != spec.effectiveKeyBits)
        {
            return false;
        }

        if (iv != null)
        {
            if (spec.iv == null)
            {
                return false;
            }

            for (int i = 0; i != iv.length; i++)
            {
                if (iv[i] != spec.iv[i])
                {
                    return false;
                }
            }
        }
        else if (spec.iv != null)
        {
            return false;
        }

        return true;
    }

    /**
     * Calculates a hash code value for the object.
     * Objects that are equal will also have the same hashcode.
     *
     * @override hashCode in class java.lang.Object
     */
    public int hashCode()
    {
        throw new RuntimeException("Not yet implemented");
    }
}
