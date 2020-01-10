package org.bouncycastle.jcajce.interfaces;

import java.security.PrivateKey;

public interface EdDSAPrivateKey
    extends EdDSAKey, PrivateKey
{
    /**
     * Return the public key associated with this private key.
     *
     * @return an EdDSAPublicKey
     */
    EdDSAPublicKey getPublicKey();
}
