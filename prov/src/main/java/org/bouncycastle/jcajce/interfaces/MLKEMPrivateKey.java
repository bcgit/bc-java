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

    /**
     * Return a privateKey which will encode as seed-only or as an expanded-key.
     *
     * @param preferSeedOnly if true, return a privateKey which will encode to seed-only if possible.
     * @return a new MLKEMPrivateKey which encodes to either seed-only or expanded-key.
     */
    MLKEMPrivateKey getPrivateKey(boolean preferSeedOnly);
}
