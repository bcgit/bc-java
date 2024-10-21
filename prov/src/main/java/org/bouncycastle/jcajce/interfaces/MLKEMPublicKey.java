package org.bouncycastle.jcajce.interfaces;

import java.security.PublicKey;

public interface MLKEMPublicKey
    extends PublicKey, MLKEMKey
{
    /**
     * Return the raw encoded data representing the public key: t || rho.
     *
     * @return the concatenation of t and rho.
     */
    byte[] getPublicData();
}
