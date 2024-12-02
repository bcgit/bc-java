package org.bouncycastle.jcajce.interfaces;

import java.security.PublicKey;

public interface SLHDSAPublicKey
    extends PublicKey, SLHDSAKey
{
    /**
     * Return the raw encoded data representing the public key: seed || root.
     *
     * @return the concatenation of the seed and root values.
     */
    byte[] getPublicData();
}
