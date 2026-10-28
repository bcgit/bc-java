package org.bouncycastle.jcajce.interfaces;

import java.security.PrivateKey;

public interface XWingPrivateKey
    extends PrivateKey, XWingKey
{
    /**
     * Return the public key corresponding to this private key.
     *
     * @return the X-Wing encapsulation key.
     */
    XWingPublicKey getPublicKey();
}
