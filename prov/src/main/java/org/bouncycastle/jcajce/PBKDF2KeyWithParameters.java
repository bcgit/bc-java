package org.bouncycastle.jcajce;

import javax.crypto.interfaces.PBEKey;

import org.bouncycastle.crypto.CharToByteConverter;
import org.bouncycastle.util.Arrays;

/**
 * A password based key for use with PBKDF2 as defined in PKCS#5 with full PBE parameters.
 */
public class PBKDF2KeyWithParameters
    extends PBKDF2Key
    implements PBEKey
{
    private final byte[] salt;
    private final int iterationCount;

    /**
     * Basic constructor for a password based key with generation parameters using FIPS PBKDF.
     *
     * @param password password to use.
     * @param converter converter to use for transforming characters into bytes.
     * @param salt salt for generation algorithm
     * @param iterationCount iteration count for generation algorithm.
     */
    public PBKDF2KeyWithParameters(char[] password, CharToByteConverter converter, byte[] salt, int iterationCount)
    {
        super(password, converter);

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
