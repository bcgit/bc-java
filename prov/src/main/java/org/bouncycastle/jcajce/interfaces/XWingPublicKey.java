package org.bouncycastle.jcajce.interfaces;

import java.security.PublicKey;

public interface XWingPublicKey
    extends PublicKey, XWingKey
{
    /**
     * Return the raw encoded data representing the public key (ML-KEM-768 encapsulation key || X25519 public key).
     *
     * @return the raw 1216 byte public key data.
     */
    byte[] getPublicData();
}
