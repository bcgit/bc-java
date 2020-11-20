package javax.crypto.spec;

import java.security.spec.AlgorithmParameterSpec;

/**
 * This class specifies the parameters used with the
 *  <a href="https://www.rsa.com/rsalabs/newfaq/q76.html"><i>RC5</i></a>
 *  algorithm.
 *  <p>
 *  The parameters consist of a version number, a rounds count, a word
 *  size, and optionally an initialization vector (IV) (only in feedback mode).
 *  <p>
 *  This class can be used to initialize a <code>Cipher</code> object that
 *  implements the <i>RC5</i> algorithm as supplied by
 *  <a href="https://www.rsa.com">RSA Data Security, Inc.</a> (RSA DSI),
 *  or any parties authorized by RSA DSI.
 */
public class RC5ParameterSpec
    implements AlgorithmParameterSpec
{
    private int     version;
    private int     rounds;
    private int     wordSize;

    private byte[]  iv;

    /**
     * Constructs a parameter set for RC5 from the given version, number of
     * rounds and word size (in bits).
     *
     * @param version the version.
     * @param rounds the number of rounds.
     * @param wordSize the word size in bits.
     */
    public RC5ParameterSpec(
        int     version,
        int     rounds,
        int     wordSize)
    {
        this.version = version;
        this.rounds = rounds;
        this.wordSize = wordSize;
        this.iv = null;
    }

    /**
     * Constructs a parameter set for RC5 from the given version, number of
     * rounds, word size (in bits), and IV.
     * <p>
     * Note that the size of the IV (block size) must be twice the word
     * size. The bytes that constitute the IV are those between
     * <code>iv[0]</code> and <code>iv[2*(wordSize/8)-1]</code> inclusive.
     *
     * @param version the version.
     * @param rounds the number of rounds.
     * @param wordSize the word size in bits.
     * @param iv the buffer with the IV.
     */
    public RC5ParameterSpec(
        int     version,
        int     rounds,
        int     wordSize,
        byte[]  iv)
    {
        this(version, rounds, wordSize, iv, 0);
    }

    /**
     * Constructs a parameter set for RC5 from the given version, number of
     * rounds, word size (in bits), and IV.
     * <p>
     * The IV is taken from <code>iv</code>, starting at <code>offset</code> inclusive.
     * Note that the size of the IV (block size), starting at
     * <code>offset</code> inclusive, must be twice the word size.
     * The bytes that constitute the IV are those between
     * <code>iv[offset]</code> and <code>iv[offset+2*(wordSize/8)-1]</code>
     * inclusive.
     *
     * @param version the version.
     * @param rounds the number of rounds.
     * @param wordSize the word size in bits.
     * @param iv the buffer with the IV.
     * @param offset the offset in <code>iv</code> where the IV starts.
     */
    public RC5ParameterSpec(
        int     version,
        int     rounds,
        int     wordSize,
        byte[]  iv,
        int     offset)
    {
        this.version = version;
        this.rounds = rounds;
        this.wordSize = wordSize;
        this.iv = new byte[2 * (wordSize / 8)];

        System.arraycopy(iv, offset, this.iv, 0, this.iv.length);
    }

    /**
     * Returns the version.
     *
     * @return the version.
     */
    public int getVersion()
    {
        return version;
    }

    /**
     * Returns the number of rounds.
     *
     * @return the number of rounds.
     */
    public int getRounds()
    {
        return rounds;
    }

    /**
     * Returns the word size in bits
     *
     * @return the word size in bits.
     */
    public int getWordSize()
    {
        return wordSize;
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
            return  null;
        }

        byte[]  tmp = new byte[iv.length];

        System.arraycopy(iv, 0, tmp, 0, iv.length);

        return tmp;
    }

    /**
     * Tests for equality between the specified object and this
     * object. Two RC5ParameterSpec objects are considered equal if their 
     * version numbers, number of rounds, word sizes, and IVs are equal.
     * (Two IV references are considered equal if both are <tt>null</tt>.)
     *
     * @param obj the object to test for equality with this object.
     * @return true if the objects are considered equal, false otherwise.
     */
    public boolean equals(
        Object  obj)
    {
        if ((obj == null) || !(obj instanceof RC5ParameterSpec))
        {
            return false;
        }

        RC5ParameterSpec spec = (RC5ParameterSpec)obj;

        if (this.version != spec.version)
        {
            return false;
        }

        if (this.rounds != spec.rounds)
        {
            return false;
        }

        if (this.wordSize != spec.wordSize)
        {
            return false;
        }

        if (iv != null)
        {
            if (spec.iv == null || spec.iv.length != iv.length)
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
     */
    public int hashCode()
    {
        int code = version ^ rounds ^ wordSize;

        if (iv != null)
        {
            for (int i = 0; i != iv.length; i++)
            {
                code ^= iv[i] << (8 * (i % 4));
            }
        }

        return code;
    }
}
