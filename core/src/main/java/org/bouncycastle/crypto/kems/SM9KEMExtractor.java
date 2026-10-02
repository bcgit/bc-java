package org.bouncycastle.crypto.kems;

import org.bouncycastle.crypto.params.SM9EncPrivateKeyParameters;
import org.bouncycastle.crypto.generators.SM9Sm3;
import org.bouncycastle.crypto.EncapsulatedSecretExtractor;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.sm9.Fp12;
import org.bouncycastle.math.ec.sm9.SM9Curve;
import org.bouncycastle.math.ec.sm9.SM9Pairing;
import org.bouncycastle.util.Arrays;

/**
 * SM9 key encapsulation mechanism - decapsulation side (GM/T 0044.4-2016, clause 6).
 * Recovers the shared key K from the encapsulation C using the user's private
 * key de: w' = e(C, de), K = KDF(C || w' || ID, klen).
 * <p>
 * <b>Usage warning:</b> an identity's encryption key should be used for this mechanism
 * or for public-key encryption ({@link org.bouncycastle.crypto.engines.SM9Engine}), but
 * not for both. Where a deployment needs both functions for one identity, the KGC
 * publishes a separate hid for each - as it already does for the key exchange - so that
 * the two user keys are distinct. That is the arrangement the exchange-versus-KEM
 * separation the constructor requires below already follows.
 */
public class SM9KEMExtractor
    implements EncapsulatedSecretExtractor
{
    private final SM9EncPrivateKeyParameters key;
    private final int keyLenBits;

    public SM9KEMExtractor(SM9EncPrivateKeyParameters key, int keyLenBits)
    {
        if (keyLenBits <= 0)
        {
            // match SM9KEMGenerator: a non-positive length has no KDF output
            throw new IllegalArgumentException("keyLenBits must be positive");
        }
        if ((keyLenBits % 8) != 0)
        {
            // the key comes back as bytes and the KDF answers only a whole number of them;
            // a request that is not one would otherwise fail inside the operation, after
            // the pairing has been paid for, rather than here where the length is chosen
            throw new IllegalArgumentException("keyLenBits must be a whole number of bytes");
        }
        if (key.isExchangeKey())
        {
            // keep the exchange and KEM usages on separate keys - a shared key
            // would give any exchange peer a pairing oracle on de
            throw new IllegalArgumentException(
                "SM9 KEM decapsulation requires an encryption user key, not a key-exchange key");
        }
        this.key = key;
        this.keyLenBits = keyLenBits;
    }

    public byte[] extractSecret(byte[] encapsulation)
    {
        if (encapsulation.length != getEncapsulationLength())
        {
            throw new IllegalArgumentException("invalid SM9 KEM encapsulation");
        }
        ECPoint c;
        try
        {
            c = SM9Curve.g1FromBytes(encapsulation, 0);
        }
        catch (IllegalArgumentException e)
        {
            // a coordinate at or above q is not a field element, and the field's own message
            // names an internal class - the same translation SM9Engine.decrypt makes for the
            // identical decode, which was not mirrored here
            throw new IllegalArgumentException("invalid SM9 KEM encapsulation");
        }
        if (c.isInfinity() || !c.isValid())
        {
            throw new IllegalArgumentException("invalid SM9 KEM encapsulation");
        }
        Fp12 w = SM9Pairing.pairing(c, key.getPrivatePoint());
        byte[] encap = SM9Curve.g1ToBytes(c);
        // taken before w is serialised, as SM9Engine and SM9KeyExchange take it: getIdentity()
        // throws for a key destroyed meanwhile, which would leave the array below unerased
        byte[] identity = key.getIdentity();
        // w is the secret K is derived from, so the array it is serialised into and the KDF input
        // built from it are erased once the KDF has read them. K itself is returned to the caller.
        byte[] wb = SM9Pairing.toBytes(w);
        byte[] z = Arrays.concatenate(encap, wb, identity);
        byte[] k;
        try
        {
            k = SM9Sm3.kdf(z, keyLenBits);
        }
        finally
        {
            Arrays.clear(z);
            Arrays.clear(wb);
        }

        // GM/T 0044.4-2016 6.2.1 B3: an all-zero K' is reported as an error and the decapsulation
        // exits. Note the asymmetry with encapsulation, where 6.1.1 A6 redraws r and tries again -
        // the receiver has no r to redraw, so it can only reject.
        if (Arrays.areAllZeroes(k, 0, k.length))
        {
            throw new IllegalArgumentException("SM9 key derivation produced an all-zero key");
        }

        return k;
    }

    public int getEncapsulationLength()
    {
        return SM9KEMGenerator.ENCAPSULATION_LENGTH;
    }
}
