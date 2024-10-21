package org.bouncycastle.jcajce.interfaces;

import java.security.PublicKey;

public interface MLDSAPublicKey
    extends PublicKey, MLDSAKey
{
    /**
     * Return the raw encoded data representing the public key: rho || t1.
     *
     * @return the concatenation of rho and t1.
     */
    byte[] getPublicData();
}
