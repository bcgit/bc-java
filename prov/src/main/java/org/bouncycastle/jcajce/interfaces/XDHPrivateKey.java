package org.bouncycastle.jcajce.interfaces;

import java.security.PrivateKey;

public interface XDHPrivateKey
    extends XDHKey, PrivateKey
{
    /**
     * Return the public key associated with this private key.
     *
     * @return an XDHPublicKey
     */
    XDHPublicKey getPublicKey();
}
