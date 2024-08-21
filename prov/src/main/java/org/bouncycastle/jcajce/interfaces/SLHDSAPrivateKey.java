package org.bouncycastle.jcajce.interfaces;

import java.security.PrivateKey;

public interface SLHDSAPrivateKey
    extends PrivateKey, SLHDSAKey
{
    /**
     * Return the public key corresponding to this private key.
     *
     * @return a SLH-DSA Public Key
     */
    SLHDSAPublicKey getPublicKey();
}
