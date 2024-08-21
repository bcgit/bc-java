package org.bouncycastle.jcajce.interfaces;

import java.security.PrivateKey;

public interface MLKEMPrivateKey
    extends PrivateKey, MLKEMKey
{
    /**
     * Return the public key corresponding to this private key.
     *
     * @return a ML-KEM Public Key
     */
    MLKEMPublicKey getPublicKey();
}
