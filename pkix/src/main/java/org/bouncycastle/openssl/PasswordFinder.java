package org.bouncycastle.openssl;

/**
 * call back to allow a password to be fetched when one is requested.
 * @deprecated no longer used.
 */
public interface PasswordFinder
{
    public char[] getPassword();
}
