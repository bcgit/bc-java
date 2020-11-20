package javax.crypto.spec;

import java.security.spec.AlgorithmParameterSpec;

/**
 * This class specifies the set of parameters used with password-based encryption (PBE), as defined in the
 * <a href="https://www.rsa.com/rsalabs/pubs/PKCS/html/pkcs-5.html">PKCS #5</a> standard.
 */
public class PBEParameterSpec
    implements AlgorithmParameterSpec
{
    private byte[]  salt;
    private int     iterationCount;

    /**
     * Constructs a parameter set for password-based encryption as defined in
     * the PKCS #5 standard.
     *
     * @param salt the salt.
     * @param iterationCount the iteration count.
     */
    public PBEParameterSpec(
        byte[]  salt,
        int     iterationCount)
    {
        this.salt = new byte[salt.length];
        System.arraycopy(salt, 0, this.salt, 0, salt.length);

        this.iterationCount = iterationCount;
    }

    /**
     * Returns the salt.
     *
     * @return the salt
     */
    public byte[] getSalt()
    {
        byte[]  tmp = new byte[salt.length];

        System.arraycopy(salt, 0, tmp, 0, salt.length);

        return tmp;
    }

    /**
     * Returns the iteration count.
     *
     * @return the iteration count
     */
    public int getIterationCount()
    {
        return iterationCount;
    }
}
