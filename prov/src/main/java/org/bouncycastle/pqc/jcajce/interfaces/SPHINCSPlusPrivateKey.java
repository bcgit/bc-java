package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.PrivateKey;

/**
 * @deprecated to be deleted - use SLH-DSA instead.
 */
@Deprecated
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
