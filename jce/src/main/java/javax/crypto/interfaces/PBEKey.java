package javax.crypto.interfaces;

import javax.crypto.SecretKey;

/**
 * The interface to a PBE key.
 * 
 * @see PBEKeySpec, SecretKey
 */
public interface PBEKey
    extends SecretKey
{
    /**
     * Returns the password.
     * 
     * Note: this method should return a copy of the password. It is the
     * caller's responsibility to zero out the password information after it is
     * no longer needed.
     * 
     * @return the password.
     */
    public char[] getPassword();

    /**
     * Returns the salt or null if not specified.
     * 
     * Note: this method should return a copy of the salt. It is the caller's
     * responsibility to zero out the salt information after it is no longer
     * needed.
     * 
     * @return the salt.
     */
    public byte[] getSalt();

    /**
     * Returns the iteration count or 0 if not specified.
     * 
     * @return the iteration count.
     */
    public int getIterationCount();
}
