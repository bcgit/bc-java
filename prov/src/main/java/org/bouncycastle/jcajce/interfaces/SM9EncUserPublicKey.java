package org.bouncycastle.jcajce.interfaces;

import java.security.PublicKey;

/**
 * Interface for an SM9 (GM/T 0044.4) recipient's encryption public key: an encryption
 * master public key bound to a recipient identity. Obtained from
 * {@link SM9EncMasterPublicKey#getUserPublicKey(byte[])}.
 * <p>
 * <b>Usage warning:</b> an identity's key should be used for {@code Cipher.SM9} or for
 * the SM9 KEM, but not for both. Which of the two an identity's key is for is the KGC's to
 * fix, by publishing a separate hid for each.
 */
public interface SM9EncUserPublicKey
    extends PublicKey
{
    /**
     * The identity this key was derived for.
     *
     * @return the recipient's identity.
     */
    byte[] getIdentity();

    /**
     * The encryption master public key this key was derived from.
     *
     * @return the encryption master public key.
     */
    SM9EncMasterPublicKey getMasterPublicKey();
}
