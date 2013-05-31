package javax.crypto.spec;

import javax.crypto.SecretKey;
import java.security.spec.KeySpec;

/**
 * This class specifies a secret key in a provider-independent fashion.
 * <p>
 * It can be used to construct a <code>SecretKey</code> from a byte array,
 * without having to go through a (provider-based)
 * <code>SecretKeyFactory</code>.
 * <p>
 * This class is only useful for raw secret keys that can be represented as
 * a byte array and have no key parameters associated with them, e.g., DES or
 * Triple DES keys.
 *
 * @see SecretKey
 * @see javax.crypto.SecretKeyFactory
 */
public class SecretKeySpec
    implements KeySpec, SecretKey
{
    private static final long serialVersionUID = 6577238317307289933L;

    private String  algorithm;
    private byte[]  key;

    /**
     * Constructs a secret key from the given byte array.
     * <p>
     * This constructor does not check if the given bytes indeed specify a
     * secret key of the specified algorithm. For example, if the algorithm is
     * DES, this constructor does not check if <code>key</code> is 8 bytes
     * long, and also does not check for weak or semi-weak keys.
     * In order for those checks to be performed, an algorithm-specific
     * <i>key specification</i> class (in this case:
     * <a href = "DESKeySpec.html"><code>DESKeySpec</code></a>)
     * should be used.
     *
     * @param key the key material of the secret key.
     * @param algorithm  the name of the secret-key algorithm to be associated
     * See Appendix A in the Java Cryptography Extension API Specification &amp; Reference 
     * for information about standard algorithm names.
     */
    public SecretKeySpec(
        byte[]  key,
        String  algorithm)
    {
        if (key == null)
        {
            throw new IllegalArgumentException("null key passed");
        }

        if (algorithm == null)
        {
            throw new IllegalArgumentException("null algorithm passed");
        }

        this.key = new byte[key.length];
        System.arraycopy(key, 0, this.key, 0, key.length);
        this.algorithm = algorithm;
    }

    /**
     * Constructs a secret key from the given byte array, using the first
     * <code>len</code> bytes of <code>key</code>, starting at
     * <code>offset</code> inclusive.
     * <p>
     * The bytes that constitute the secret key are those between <code>key[offset]</code> and
     * <code>key[offset+len-1]</code> inclusive.
     * <p>
     * This constructor does not check if the given bytes indeed specify a
     * secret key of the specified algorithm. For example, if the algorithm is
     * DES, this constructor does not check if <code>key</code> is 8 bytes
     * long, and also does not check for weak or semi-weak keys.
     * In order for those checks to be performed, an algorithm-specific key
     * specification class (in this case: <a href = "DESKeySpec.html"><code>DESKeySpec</code></a>)
     * must be used.
     *
     * @param key the key material of the secret key.
     * @param offset the offset in <code>key</code> where the key material starts.
     * @param len the length of the key material.
     * @param algorithm the name of the secret-key algorithm to be associated
     * with the given key material. See Appendix A in the Java Cryptography Extension API
     * Specification &amp; Reference for information about standard algorithm names.
     */
    public SecretKeySpec(
        byte[]      key,
        int         offset,
        int         len,
        String      algorithm)
    {
        if (key == null)
        {
            throw new IllegalArgumentException("Null key passed");
        }

        if ((key.length - offset) < len)
        {
            throw new IllegalArgumentException("Bad offset/len");
        }

        if (algorithm == null)
        {
            throw new IllegalArgumentException("Null algorithm string passed");
        }

        this.key = new byte[len];
        System.arraycopy(key, offset, this.key, 0, len);
        this.algorithm = algorithm;
    }

    /**
     * Returns the name of the algorithm associated with this secret key.
     *
     * @return the secret key algorithm.
     */
    public String getAlgorithm()
    {
        return algorithm;
    }

    /**
     * Returns the name of the encoding format for this secret key.
     *
     * @return the string "RAW".
     */
    public java.lang.String getFormat()
    {
        return "RAW";
    }

    /**
     * Returns the key material of this secret key.
     *
     * @return the key material
     */
    public byte[] getEncoded()
    {
        byte[]  tmp = new byte[key.length];

        System.arraycopy(key, 0, tmp, 0, tmp.length);

        return tmp;
    }

    /**
     * Calculates a hash code value for the object.
     * Objects that are equal will also have the same hashcode.
     */
    public int hashCode()
    {
        int code = algorithm.toUpperCase().hashCode();

        for (int i = 0; i != this.key.length; i++)
        {
            code ^= this.key[i] << (8 * (i % 4));
        }

        return code;
    }

    public boolean equals(
        Object  obj)
    {
        if ((obj == null) || !(obj instanceof SecretKeySpec))
        {
            return false;
        }

        SecretKeySpec spec = (SecretKeySpec)obj;

        if (!this.algorithm.equalsIgnoreCase(spec.algorithm))
        {
            return false;
        }

        if (this.key.length != spec.key.length)
        {
            return false;
        }

        for (int i = 0; i != this.key.length; i++)
        {
            if (this.key[i] != spec.key[i])
            {
                return false;
            }
        }

        return true;
    }
}
