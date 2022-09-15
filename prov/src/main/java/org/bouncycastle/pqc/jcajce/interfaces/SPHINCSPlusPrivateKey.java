package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.PrivateKey;

public interface SPHINCSPlusPrivateKey
    extends PrivateKey, SPHINCSPlusKey
{
    /**
     * Return the public key corresponding to this private key.
     *
     * @return a SPHINCS+ Public Key
     */
    SPHINCSPlusPublicKey getPublicKey();
}
