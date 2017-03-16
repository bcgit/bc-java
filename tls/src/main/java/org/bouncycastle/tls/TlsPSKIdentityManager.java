package org.bouncycastle.tls;

/**
 * Base interface for an object that can process a PSK identity.
 */
public interface TlsPSKIdentityManager
{
    byte[] getHint();

    byte[] getPSK(byte[] identity);
}
