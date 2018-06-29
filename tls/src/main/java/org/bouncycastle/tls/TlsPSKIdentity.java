package org.bouncycastle.tls;

/**
 * Processor interface for a PSK identity.
 */
public interface TlsPSKIdentity
{
    void skipIdentityHint();

    void notifyIdentityHint(byte[] psk_identity_hint);

    byte[] getPSKIdentity();

    byte[] getPSK();
}
