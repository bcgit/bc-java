package org.bouncycastle.crypto.params;

import javax.security.auth.Destroyable;

import org.bouncycastle.math.ec.sm9.SM9G2Point;
import org.bouncycastle.util.Arrays;

/**
 * A user's SM9 encryption private key de = [t2]P2, a point of G2
 * (GM/T 0044.4-2016). Carries the master public key and the user's identity,
 * both needed to decapsulate/decrypt (the identity is part of the KDF input).
 */
public class SM9EncPrivateKeyParameters
    extends AsymmetricKeyParameter
    implements Destroyable
{
    private SM9G2Point de;
    private volatile boolean destroyed;
    private final SM9EncMasterPublicKeyParameters masterPublicKey;
    private final byte[] identity;

    SM9EncPrivateKeyParameters(SM9G2Point de, SM9EncMasterPublicKeyParameters masterPublicKey, byte[] identity)
    {
        super(true);
        this.de = de;
        this.masterPublicKey = masterPublicKey;
        this.identity = identity;
    }

    public SM9G2Point getPrivatePoint()
    {
        return checkedDe();
    }

    public SM9EncMasterPublicKeyParameters getMasterPublicKey()
    {
        return masterPublicKey;
    }

    public byte[] getIdentity()
    {
        byte[] id = Arrays.clone(identity);
        if (destroyed)
        {
            throw new IllegalStateException("key destroyed");
        }
        return id;
    }

    /**
     * The user's encryption private key point de of G2 in uncompressed form
     * (0x04 || x || y, 129 bytes). The master public key and identity are not
     * part of this encoding; supply them via {@link #fromEncoded} to rebuild a
     * usable key (the identity is part of the decryption KDF input).
     */
    public byte[] getEncoded()
    {
        return checkedDe().getEncoded();
    }

    public static SM9EncPrivateKeyParameters fromEncoded(
        byte[] enc, SM9EncMasterPublicKeyParameters masterPublicKey, byte[] identity)
    {
        return new SM9EncPrivateKeyParameters(SM9G2Point.decode(enc), masterPublicKey, Arrays.clone(identity));
    }

    /**
     * Destroy this object, dropping its reference to the private point de and
     * zeroizing the identity.
     * <p>
     * As the point's coordinates are immutable they cannot be zeroized in place;
     * destruction drops the reference and marks the key destroyed, after which
     * {@link #getPrivatePoint()}, {@link #getEncoded()} and {@link #getIdentity()}
     * throw {@link IllegalStateException}. The master public key remains available.
     */
    public synchronized void destroy()
    {
        if (!destroyed)
        {
            destroyed = true;
            de = null;
            Arrays.clear(identity);
        }
    }

    public boolean isDestroyed()
    {
        return destroyed;
    }

    private SM9G2Point checkedDe()
    {
        // the null check catches a destroy() in progress whose flag write is not yet visible;
        // as the point is immutable a non-null snapshot is always the intact pre-destroy value.
        SM9G2Point value = this.de;
        if (destroyed || value == null)
        {
            throw new IllegalStateException("key destroyed");
        }
        return value;
    }
}
