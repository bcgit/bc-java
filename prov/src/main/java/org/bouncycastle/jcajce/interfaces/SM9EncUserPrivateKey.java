package org.bouncycastle.jcajce.interfaces;

import java.security.PrivateKey;

/**
 * Interface for a user's SM9 (GM/T 0044.4) encryption (KEM / decryption) private key (de),
 * derived by the KGC from the encryption master private key and the user's identity.
 * <p>
 * <b>Usage warning:</b> one identity's key should be used for {@code Cipher.SM9} or for
 * the SM9 KEM ({@code KeyGenerator.SM9-KEM}, {@code KEM.SM9-KEM}), but not for both. A
 * deployment needing both has its KGC publish a separate hid for each function, as it
 * already does for the key exchange, so that the two keys are distinct.
 */
public interface SM9EncUserPrivateKey
    extends PrivateKey
{
    /**
     * The identity this key was derived for.
     *
     * @return the user's identity.
     */
    byte[] getIdentity();
}
