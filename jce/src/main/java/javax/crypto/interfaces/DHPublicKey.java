package javax.crypto.interfaces;

import java.math.BigInteger;
import java.security.PublicKey;

/**
 * The interface to a Diffie-Hellman public key.
 *
 * @see DHKey
 * @see DHPrivateKey
 */
public abstract interface DHPublicKey
    extends DHKey, PublicKey
{
    /**
     * Returns the public value, <code>y</code>.
     *
     * @return the public value, <code>y</code>
     */
    public BigInteger getY();
}
