package org.bouncycastle.jcajce.interfaces;

import java.security.PrivateKey;

public interface MLDSAPrivateKey
    extends PrivateKey, MLDSAKey
{
    /**
     * Return the public key corresponding to this private key.
     *
     * @return a ML-DSA Public Key
     */
    MLDSAPublicKey getPublicKey();
}
