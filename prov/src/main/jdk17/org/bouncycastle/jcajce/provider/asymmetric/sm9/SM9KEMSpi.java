package org.bouncycastle.jcajce.provider.asymmetric.sm9;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KEMSpi;

import org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.KdfUtil;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;

/**
 * {@link javax.crypto.KEM} support for the SM9 identity-based key encapsulation
 * mechanism (GM/T 0044.4-2016), registered as {@code KEM.SM9-KEM}. The encapsulator
 * takes a user public key (from
 * {@link org.bouncycastle.jcajce.interfaces.SM9EncMasterPublicKey#getUserPublicKey(byte[])}),
 * the decapsulator the matching user private key.
 * <p>
 * With a null spec (or {@link KTSParameterSpec.Builder#withNoKdf()}) the shared secret is
 * the mechanism's own GM/T 0044.4 KDF output at the requested size - the interoperable
 * form. A {@link KTSParameterSpec} KDF may optionally be layered on top for generic use;
 * the GM/T 0044.4 KDF then first produces a 256-bit shared secret which is passed to the
 * configured KDF. Note an external KDF is not part of GM/T 0044.4, so the result will not
 * interoperate with other SM9 implementations.
 * <p>
 * <b>Usage warning:</b> an identity's key should be used for this service or for
 * {@code Cipher.SM9}, but not for both, whether or not a KTSParameterSpec KDF is layered on
 * top. A deployment needing both has its KGC publish a separate hid for each function, as
 * it already does for the key exchange, so that the two keys are distinct.
 */
public class SM9KEMSpi
    implements KEMSpi
{
    @Override
    public EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey, AlgorithmParameterSpec spec,
        SecureRandom secureRandom) throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        if (!(publicKey instanceof BCSM9EncPublicKey bcPublicKey))
        {
            throw new InvalidKeyException("unsupported key type");
        }
        if (bcPublicKey.getKeyParameters().getHid() == SM9EncMasterPrivateKeyParameters.HID_EXCHANGE)
        {
            // SM9KEMGenerator refuses a recipient key under the exchange's hid with an unchecked
            // IllegalArgumentException, which would come out of encapsulate(); the key is the wrong
            // kind of key, which is what InvalidKeyException is for, as on the decapsulator side
            throw new InvalidKeyException(
                "SM9 KEM encapsulation requires an encryption recipient key, not a key-exchange key under HID_EXCHANGE (0x02)");
        }

        KTSParameterSpec kts = resolveSpec(spec);

        return new SM9EncapsulatorSpi(bcPublicKey, kts, secureRandom);
    }

    @Override
    public DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec)
        throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        if (!(privateKey instanceof BCSM9EncPrivateKey bcPrivateKey))
        {
            throw new InvalidKeyException("unsupported key type");
        }
        if (bcPrivateKey.isDestroyed())
        {
            // refused here rather than taken and left to fail in decapsulate(), as an
            // IllegalStateException where the contract names only DecapsulateException
            throw new InvalidKeyException("key destroyed");
        }
        if (bcPrivateKey.getKeyParameters().isExchangeKey())
        {
            // SM9KEMExtractor refuses a key-exchange key with an unchecked IllegalArgumentException
            // from its constructor, which escaped newDecapsulator; the key is the wrong kind of key,
            // which is what InvalidKeyException is for
            throw new InvalidKeyException(
                "SM9 KEM decapsulation requires an encryption user key, not a key-exchange key");
        }

        KTSParameterSpec kts = resolveSpec(spec);

        return new SM9DecapsulatorSpi(bcPrivateKey, kts);
    }

    /**
     * Validate the spec both sides take, or build the default: the one copy of what the
     * encapsulator and decapsulator used to repeat verbatim.
     * <p>
     * SM9 sizes its secret from the spec itself and so does not go through
     * KdfUtil.resolveKemSpec, but it applies that method's rules: a null key algorithm name would
     * be substituted for a "Generic" request and only fail deep inside the derivation; the key
     * size must be a positive whole number of bytes, since javax.crypto.KEM validates
     * encapsulate()'s range against secretSize(), which is one - a size below 8 floored to a
     * zero-length SecretKey and any other silently delivered fewer bits; and a KDF this provider
     * cannot service is refused here rather than surfacing from encapsulate() or decapsulate() as
     * an unchecked exception, which is not the DecapsulateException the contract names.
     */
    private static KTSParameterSpec resolveSpec(AlgorithmParameterSpec spec)
        throws InvalidAlgorithmParameterException
    {
        if (spec == null)
        {
            // No KDF - the shared secret is SM9's own GM/T 0044.4 KDF output.
            return new KTSParameterSpec.Builder("Generic", 256).withNoKdf().build();
        }
        if (!(spec instanceof KTSParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("SM9-KEM can only accept KTSParameterSpec");
        }
        KTSParameterSpec kts = (KTSParameterSpec)spec;
        if (kts.getKeyAlgorithmName() == null)
        {
            throw new InvalidAlgorithmParameterException("KTSParameterSpec has no key algorithm name");
        }
        if (kts.getKeySize() <= 0 || (kts.getKeySize() % 8) != 0)
        {
            throw new InvalidAlgorithmParameterException(
                "KTSParameterSpec key size must be a positive whole number of bytes: " + kts.getKeySize());
        }
        KdfUtil.checkKdfSupported(kts);
        return kts;
    }
}
