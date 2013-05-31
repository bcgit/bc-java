package javax.crypto;

import java.security.Key;

/**
 * A secret (symmetric) key.
 * <p>
 * This interface contains no methods or constants.
 * Its only purpose is to group (and provide type safety for) secret keys.
 * <p>
 * Provider implementations of this interface must overwrite the
 * <code>equals</code> and <code>hashCode</code> methods inherited from
 * <code>java.lang.Object</code>, so that secret keys are compared based on
 * their underlying key material and not based on reference.
 * <p>
 * Keys that implement this interface return the string <code>RAW</code>
 * as their encoding format (see <code>getFormat</code>), and return the
 * raw key bytes as the result of a <code>getEncoded</code> method call. (The
 * <code>getFormat</code> and <code>getEncoded</code> methods are inherited
 * from the <code>java.security.Key</code> parent interface.)
 *
 * @see SecretKeyFactory
 * @see Cipher
 */
public abstract interface SecretKey
    extends Key
{
}
