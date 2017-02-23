package org.bouncycastle.est;

/**
 * TLSUniqueProvider implementation of this can provide the TLS unique value.
 */
public interface TLSUniqueProvider
{
    byte[] getTLSUnique();
}
