package org.bouncycastle.est;

/**
 * TLSUniqueProvider implementation of this can provide the TLS unique value.
 */
public interface TLSUniqueProvider
{
    /**
     * Return true if a TLS unique value should be available.
     *
     * @return true if a TLS unique should be available, false otherwise.
     */
    boolean isTLSUniqueAvailable();

    /**
     * Return the TLS unique value.
     *
     * @return a TLS unique value.
     */
    byte[] getTLSUnique();
}
