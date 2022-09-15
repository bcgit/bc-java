package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.PrivateKey;

public interface DilithiumPrivateKey
    extends PrivateKey, DilithiumKey
{
    /**
     * Return the public key corresponding to this private key.
     *
     * @return a Dilithium Public Key
     */
    DilithiumPublicKey getPublicKey();
}
