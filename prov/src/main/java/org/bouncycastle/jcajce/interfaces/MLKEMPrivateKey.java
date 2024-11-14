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

    /**
     * Return the long form private data for the ML-KEM private key.
     *
     * @return long form private data for private key.
     */
    byte[] getPrivateData();

    /**
     * Return the seed the private key was generated from (if available).
     *
     * @return the seed for the private key, null if not available.
     */
    byte[] getSeed();
}
