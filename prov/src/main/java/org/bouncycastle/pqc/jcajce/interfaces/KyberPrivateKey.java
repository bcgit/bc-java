package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.PrivateKey;

public interface KyberPrivateKey
    extends PrivateKey, KyberKey
{
    /**
     * Return the public key corresponding to this private key.
     *
     * @return a Kyber Public Key
     */
    KyberPublicKey getPublicKey();
}
