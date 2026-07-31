package org.bouncycastle.jcajce.provider.asymmetric.sm9;

import java.io.NotSerializableException;
import java.io.ObjectStreamException;
import java.security.PublicKey;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.sm9.SM9Curve;
import org.bouncycastle.util.Arrays;

/**
 * A party's ephemeral value R for the SM9 key exchange (GM/T 0044.3-2016), a
 * point of G1 - a protocol message rather than a durable key. It is returned by
 * the first {@code doPhase} of {@code KeyAgreement.SM9} (its
 * {@link #getEncoded()} is the standard's 64-byte x || y form to send), and the
 * value received from the peer is wrapped with
 * {@link org.bouncycastle.jcajce.interfaces.SM9EncMasterPublicKey#getExchangeEphemeral(byte[])}
 * - which rejects a point not on the curve - to be passed to the final
 * {@code doPhase}. It carries no key material of its own: the ephemeral scalar
 * never leaves the provider.
 * <p>
 * Package-private by design - a caller only ever holds it as a
 * {@link java.security.Key}, so it is not part of the provider's API surface.
 */
class BCSM9ExchangeEphemeralPublicKey
    implements PublicKey
{
    private static final long serialVersionUID = 1L;

    private final transient ECPoint point;

    BCSM9ExchangeEphemeralPublicKey(ECPoint point)
    {
        this.point = point;
    }

    /**
     * Wrap a peer's ephemeral value as received - reached through
     * {@link org.bouncycastle.jcajce.interfaces.SM9EncMasterPublicKey#getExchangeEphemeral(byte[])}.
     */
    BCSM9ExchangeEphemeralPublicKey(byte[] encoded)
    {
        if (encoded == null || encoded.length != 64)
        {
            throw new IllegalArgumentException("SM9 exchange ephemeral encoding must be 64 bytes");
        }
        ECPoint p = SM9Curve.g1FromBytes(encoded, 0);
        if (p.isInfinity() || !p.isValid())
        {
            throw new IllegalArgumentException("invalid SM9 exchange ephemeral point");
        }
        this.point = p.normalize();
    }

    ECPoint getPoint()
    {
        return point;
    }

    public String getAlgorithm()
    {
        return "SM9";
    }

    public String getFormat()
    {
        return "RAW";
    }

    /**
     * The ephemeral point R as the standard's x || y form (64 bytes).
     */
    public byte[] getEncoded()
    {
        return SM9Curve.g1ToBytes(point);
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }
        if (!(o instanceof BCSM9ExchangeEphemeralPublicKey))
        {
            return false;
        }
        return Arrays.areEqual(getEncoded(), ((BCSM9ExchangeEphemeralPublicKey)o).getEncoded());
    }

    public int hashCode()
    {
        return Arrays.hashCode(getEncoded());
    }

    private Object writeReplace()
        throws ObjectStreamException
    {
        throw new NotSerializableException(
            "SM9 exchange ephemeral keys are not serializable; transport the getEncoded() form");
    }
}
