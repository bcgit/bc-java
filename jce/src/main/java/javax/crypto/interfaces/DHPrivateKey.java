package javax.crypto.interfaces;

import java.math.BigInteger;
import java.security.PrivateKey;

/**
 * The interface to a Diffie-Hellman private key.
 *
 * @see DHKey
 * @see DHPublicKey
 */
public abstract interface DHPrivateKey
    extends DHKey, PrivateKey
{
    /**
     * Returns the private value, <code>x</code>.
     *
     * @return the private value, <code>x</code>
     */
    public BigInteger getX();
}
