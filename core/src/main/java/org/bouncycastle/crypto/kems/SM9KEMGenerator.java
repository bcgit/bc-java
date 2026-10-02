package org.bouncycastle.crypto.kems;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9EncMasterPublicKeyParameters;
import org.bouncycastle.crypto.params.SM9EncPublicKeyParameters;
import org.bouncycastle.crypto.generators.SM9Sm3;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.sm9.Fp12;
import org.bouncycastle.math.ec.sm9.SM9Curve;
import org.bouncycastle.math.ec.sm9.SM9Pairing;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * SM9 key encapsulation mechanism - encapsulation side (GM/T 0044.4-2016, clause 6).
 * Given a recipient identity and the encryption master public key, produces a
 * shared key K and its encapsulation C = [r]Q_B (a G1 point, encoded x||y).
 * <p>
 * <b>Usage warning:</b> an identity's encryption key should be used for this mechanism
 * or for public-key encryption ({@link org.bouncycastle.crypto.engines.SM9Engine}), but
 * not for both. A deployment needing both has its KGC publish a separate hid for each
 * function, as it already does for the key exchange, so that the two keys are distinct.
 */
public class SM9KEMGenerator
    implements EncapsulatedSecretGenerator
{
    /**
     * Draws of r allowed for one encapsulation. A draw is discarded when it falls outside [1, N-1],
     * which a draw of N's bit length does with probability under 0.29, or when the derived key comes
     * out all zero, the standard's own retry, with probability 2^-klen. Needing this many draws in a
     * row has a probability below 2^-220, so reaching it means the random source is not producing
     * usable values rather than that the draws were unlucky.
     */
    private static final int MAX_REDRAWS = 128;

    /**
     * The length in bytes of an SM9 KEM encapsulation: C = [r]Q_B, a G1 point written as x || y.
     * The one value both the generator's and the extractor's sides report, so the two cannot drift.
     */
    public static final int ENCAPSULATION_LENGTH = 64;

    private final int keyLenBits;
    private final SecureRandom random;

    public SM9KEMGenerator(int keyLenBits, SecureRandom random)
    {
        if (keyLenBits <= 0)
        {
            // a non-positive length gives the KDF nothing to produce, so the
            // all-zero retry check would hold vacuously and never terminate
            throw new IllegalArgumentException("keyLenBits must be positive");
        }
        if ((keyLenBits % 8) != 0)
        {
            // the key comes back as bytes and the KDF answers only a whole number of them;
            // a request that is not one would otherwise fail inside the operation, after
            // the ephemeral has been drawn, rather than here where the length is chosen
            throw new IllegalArgumentException("keyLenBits must be a whole number of bytes");
        }
        this.keyLenBits = keyLenBits;
        this.random = random;
    }

    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey)
    {
        if (!(recipientKey instanceof SM9EncPublicKeyParameters))
        {
            throw new IllegalArgumentException("SM9 KEM encapsulation requires an SM9EncPublicKeyParameters recipient key");
        }
        SM9EncPublicKeyParameters rk = (SM9EncPublicKeyParameters)recipientKey;
        if (rk.getHid() == SM9EncMasterPrivateKeyParameters.HID_EXCHANGE)
        {
            // the extractor's refusal of a key-exchange key, made where the sender can see it: no
            // decapsulation key can be derived under the exchange's hid, so a key encapsulated to
            // a recipient key formed under it could never be recovered, and the mistake only
            // showed once the recipient tried
            throw new IllegalArgumentException(
                "SM9 KEM encapsulation requires an encryption recipient key, not a key-exchange key under HID_EXCHANGE (0x02)");
        }
        SM9EncMasterPublicKeyParameters master = rk.getMasterPublicKey();
        byte[] identity = rk.getIdentity();

        Fp12 g = master.pairingWithP2();
        SecureRandom rand = CryptoServicesRegistrar.getSecureRandom(random);
        BigInteger n = SM9Curve.N;

        for (int attempt = 0; ; ++attempt)
        {
            if (attempt == MAX_REDRAWS)
            {
                // GM/T 0044.4 6.1.1 A6 redraws r on an all-zero K and does not bound the redraws,
                // because each is independent with probability 2^-klen. A source that yields nothing
                // usable - only zeros, say - would make the loop spin rather than fail, so it is
                // bounded: reaching this many draws is not a chance event.
                throw new IllegalStateException("SM9 encapsulation could not draw a usable ephemeral");
            }
            // A1: r in [1, N-1], drawn and range-checked here rather than by
            // BigIntegers.createRandomInRange, which after a thousand draws out of range falls back
            // to one that cannot fail - for a source that yields only zeros, r = 1
            BigInteger r = BigIntegers.createRandomBigInteger(n.bitLength(), rand);
            if (r.signum() == 0 || r.compareTo(n) >= 0)
            {
                continue;
            }
            // C = [r]Q_B, formed without forming Q_B - see multiplyRecipientPoint, which refuses an
            // identity whose Q_B is the point at infinity as recipientPoint does
            ECPoint c = master.multiplyRecipientPoint(identity, rk.getHid(), r);
            Fp12 w = g.powSecureFixedBase(r);
            byte[] encap = SM9Curve.g1ToBytes(c);
            // w is the secret K is derived from, so the array it is serialised into and the KDF input
            // built from it are erased once the KDF has read them. K itself goes to the caller, who
            // can erase it through the result's destroy().
            byte[] wb = SM9Pairing.toBytes(w);
            byte[] z = Arrays.concatenate(encap, wb, identity);
            byte[] key;
            try
            {
                key = SM9Sm3.kdf(z, keyLenBits);
            }
            finally
            {
                Arrays.clear(z);
                Arrays.clear(wb);
            }
            if (!Arrays.areAllZeroes(key, 0, key.length))
            {
                return new SecretWithEncapsulationImpl(key, encap);
            }
        }
    }
}
