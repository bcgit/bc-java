package org.bouncycastle.jcajce.interfaces;

import java.security.PublicKey;

public interface FrodoKEMPublicKey
    extends PublicKey, FrodoKEMKey
{
    /**
     * Return the raw encoded data representing the public key (seedA || b).
     *
     * @return the raw public key data.
     */
    byte[] getPublicData();
}
