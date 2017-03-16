package org.bouncycastle.tls;

public interface TlsPSKIdentity
{
    void skipIdentityHint();

    void notifyIdentityHint(byte[] psk_identity_hint);

    byte[] getPSKIdentity();

    byte[] getPSK();
}
