package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.PrivateKey;

public interface FalconPrivateKey
    extends PrivateKey, FalconKey
{
    /**
     * Return the public key corresponding to this private key.
     *
     * @return a Falcon Public Key
     */
    FalconPublicKey getPublicKey();
}
