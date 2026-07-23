package org.bouncycastle.jcajce.provider.asymmetric.sm9;

import java.io.InvalidObjectException;
import java.io.ObjectStreamException;
import java.io.Serializable;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Serialization proxy for the SM9 <b>master</b> key wrappers. It stores only the
 * standard encoded form and reconstructs the key on deserialization through the
 * SM9 {@link KeyFactorySpi}, so the (non-Serializable) lightweight key parameters
 * are never serialized directly - avoiding the silent {@code null} keyParams that
 * a plain {@code transient} field would leave after deserialization.
 * <p>
 * User identity keys are not standalone-decodable (their encoding omits the master
 * public key), so they are not serializable; their {@code writeReplace} throws
 * rather than routing through this proxy.
 */
class SM9KeyProxy
    implements Serializable
{
    private static final long serialVersionUID = 1L;

    private final boolean isPrivate;
    private final byte[] encoded;

    SM9KeyProxy(boolean isPrivate, byte[] encoded)
    {
        this.isPrivate = isPrivate;
        this.encoded = encoded;
    }

    private Object readResolve()
        throws ObjectStreamException
    {
        try
        {
            KeyFactorySpi keyFactory = new KeyFactorySpi();
            if (isPrivate)
            {
                return keyFactory.engineGeneratePrivate(new PKCS8EncodedKeySpec(encoded));
            }
            return keyFactory.engineGeneratePublic(new X509EncodedKeySpec(encoded));
        }
        catch (Exception e)
        {
            throw new InvalidObjectException("unable to reconstruct SM9 key: " + e.getMessage());
        }
    }
}
