package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.PrivateKey;

public interface RainbowPrivateKey
    extends PrivateKey, RainbowKey
{
    /**
     * Return the public key corresponding to this private key.
     *
     * @return a Rainbow Public Key
     */
    RainbowPublicKey getPublicKey();
}
