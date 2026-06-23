package org.bouncycastle.jcajce.interfaces;

import java.security.PublicKey;

public interface CMCEPublicKey
    extends PublicKey, CMCEKey
{
    /**
     * Return the raw encoded data representing the public key.
     *
     * @return the raw public key data.
     */
    byte[] getPublicData();
}
