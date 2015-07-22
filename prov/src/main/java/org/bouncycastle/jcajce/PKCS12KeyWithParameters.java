package org.bouncycastle.jcajce;

import javax.crypto.interfaces.PBEKey;

import org.bouncycastle.util.Arrays;

/**
 * A password based key for use with PKCS#12 with full PBE parameters.
 */
public class PKCS12KeyWithParameters
    extends PKCS12Key
    implements PBEKey
{
    private final byte[] salt;
    private final int iterationCount;

    /**
     * Basic constructor for a password based key with generation parameters.
     *
     * @param password password to use.
     * @param salt salt for generation algorithm
     * @param iterationCount iteration count for generation algorithm.
     */
    public PKCS12KeyWithParameters(char[] password, byte[] salt, int iterationCount)
    {
        super(password);

        this.salt = Arrays.clone(salt);
        this.iterationCount = iterationCount;
    }


    /**
     * Basic constructor for a password based key with generation parameters, specifying the wrong conversion for
     * zero length passwords.
     *
     * @param password password to use.
     * @param salt salt for generation algorithm
     * @param iterationCount iteration count for generation algorithm.
     * @param useWrongZeroLengthConversion use the incorrect encoding approach (add pad bytes)
     */
    public PKCS12KeyWithParameters(char[] password, boolean useWrongZeroLengthConversion, byte[] salt, int iterationCount)
    {
        super(password, useWrongZeroLengthConversion);

        this.salt = Arrays.clone(salt);
        this.iterationCount = iterationCount;
    }

    /**
     * Return the salt to use in the key derivation function.
     *
     * @return the salt to use in the KDF.
     */
    public byte[] getSalt()
    {
        return salt;
    }

    /**
     * Return the iteration count to use in the key derivation function.
     *
     * @return the iteration count to use in the KDF.
     */
    public int getIterationCount()
    {
        return iterationCount;
    }
}
