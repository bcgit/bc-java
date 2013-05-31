package javax.crypto.spec;

import java.security.spec.KeySpec;

import javax.crypto.SecretKeyFactory;

/**
 * A user-chosen password that can be used with password-based encryption (PBE).
 * <p>
 * The password can be viewed as some kind of raw key material, from which the
 * encryption mechanism that uses it derives a cryptographic key.
 * <p>
 * Different PBE mechanisms may consume different bits of each password
 * character. For example, the PBE mechanism defined in PKCS #5 looks at only
 * the low order 8 bits of each character, whereas PKCS #12 looks at all 16 bits
 * of each character.
 * <p>
 * You convert the password characters to a PBE key by creating an instance of
 * the appropriate secret-key factory. For example, a secret-key factory for
 * PKCS #5 will construct a PBE key from only the low order 8 bits of each
 * password character, whereas a secret-key factory for PKCS #12 will take all
 * 16 bits of each character.
 * <p>
 * Also note that this class stores passwords as char arrays instead of String
 * objects (which would seem more logical), because the String class is
 * immutable and there is no way to overwrite its internal value when the
 * password stored in it is no longer needed. Hence, this class requests the
 * password as a char array, so it can be overwritten when done.
 * 
 * @see SecretKeyFactory
 * @see PBEParameterSpec
 */
public class PBEKeySpec
    implements KeySpec
{

    private char[] password;

    private byte[] salt;

    private int iterationCount;

    private int keyLength;

    private boolean isPasswordCleared;

    /**
     * Constructor that takes a password. An empty char[] is used if null is
     * specified.
     * <p>
     * Note: password is cloned before it is stored in the new PBEKeySpec
     * object.
     * 
     * @param password -
     *            the password.
     */
    public PBEKeySpec(char[] password)
    {
        if (password == null)
        {
            this.password = new char[0];
        }
        else
        {
            this.password = new char[password.length];

            System.arraycopy(password, 0, this.password, 0, password.length);
        }
    }

    /**
     * Returns a copy of the password.
     * <p>
     * Note: this method returns a copy of the password. It is the caller's
     * responsibility to zero out the password information after it is no longer
     * needed.
     * 
     * @return the password
     * @throws IllegalStateException -
     *             if password has been cleared by calling clearPassword method.
     */
    public final char[] getPassword()
    {
        if (isPasswordCleared)
        {
            throw new IllegalStateException("Password has been cleared");
        }
        return password;
    }

    /**
     * Constructor that takes a password, salt, iteration count, and
     * to-be-derived key length for generating PBEKey of variable-key-size PBE
     * ciphers. An empty char[] is used if null is specified for password.
     * <p>
     * Note: the password and salt are cloned before they are stored in the new
     * PBEKeySpec object.
     * 
     * 
     * @param password
     *            password - the password.
     * @param salt
     *            salt - the salt.
     * @param iterationCount
     *            iterationCount - the iteration count.
     * @param keyLength
     *            keyLength - the to-be-derived key length.
     * @throws NullPointerException -
     *             if salt is null.
     * @throws IllegalArgumentException -
     *             if salt is empty, i.e. 0-length, iterationCount or keyLength
     *             is not positive.
     */
    public PBEKeySpec(char[] password, byte[] salt, int iterationCount, int keyLength)
    {
        this(password);
        if (salt == null)
        {
            throw new NullPointerException("salt is null");
        }
        if (salt.length == 0)
        {
            throw new IllegalArgumentException("salt is empty");
        }
        if (iterationCount < 0)
        {
            throw new IllegalArgumentException("iterationCount is not positive");
        }
        if (keyLength < 0)
        {
            throw new IllegalArgumentException("keyLength is not positive");
        }
        this.keyLength = keyLength;
        this.iterationCount = iterationCount;
        this.salt = (byte[]) salt.clone();
    }

    /**
     * Constructor that takes a password, salt, iteration count for generating
     * PBEKey of fixed-key-size PBE ciphers. An empty char[] is used if null is
     * specified for password.
     * <p>
     * Note: the password and salt are cloned before they are stored in the new
     * PBEKeySpec object.
     * 
     * @param password -
     *            the password.
     * @param salt -
     *            the salt.
     * @param iterationCount -
     *            the iteration count.
     * @throws NullPointerException -
     *             if salt is null.
     * @throws IllegalArgumentException -
     *             if salt is empty, i.e. 0-length, or iterationCount is not
     *             positive.
     */
    public PBEKeySpec(char[] password, byte[] salt, int iterationCount)
    {
        this(password, salt, iterationCount, 0);
    }

    /**
     * Clears the internal copy of the password.
     */
    public final void clearPassword()
    {
        for (int i = 0; i < password.length; i++)
        {
            password[i] = 0;
        }
        password = null;
        isPasswordCleared = true;
    }

    /**
     * Returns a copy of the salt or null if not specified.
     * 
     * Note: this method should return a copy of the salt. It is the caller's
     * responsibility to zero out the salt information after it is no longer
     * needed.
     * 
     * @return the salt.
     */
    public final byte[] getSalt()
    {
        if (salt != null)
        {
            byte[] tmp = new byte[salt.length];

            System.arraycopy(salt, 0, tmp, 0, salt.length);

            return tmp;
        }

        return null;
    }

    /**
     * Returns the iteration count or 0 if not specified.
     * 
     * @return the iteration count.
     */
    public final int getIterationCount()
    {
        return iterationCount;
    }

    /**
     * Returns the to-be-derived key length or 0 if not specified.
     * <p>
     * Note: this is used to indicate the preference on key length for
     * variable-key-size ciphers. The actual key size depends on each provider's
     * implementation.
     * 
     * @return the to-be-derived key length.
     */
    public final int getKeyLength()
    {
        return keyLength;
    }
}
