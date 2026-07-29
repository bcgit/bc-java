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
        ECPoint c = SM9Curve.g1FromBytes(encapsulation, 0);
        if (c.isInfinity() || !c.isValid())
        {
            throw new IllegalArgumentException("invalid SM9 KEM encapsulation");
        }
        Fp12 w = SM9Pairing.pairing(c, key.getPrivatePoint());
        byte[] encap = SM9Curve.g1ToBytes(c);
        return SM9Sm3.kdf(Arrays.concatenate(encap, SM9Pairing.toBytes(w), key.getIdentity()), keyLenBits);
    }

    public int getEncapsulationLength()
    {
        return 64;
    }
}
