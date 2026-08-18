package org.bouncycastle.jcajce.provider.asymmetric.sm9;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KEMSpi;

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

        if (spec == null)
        {
            // No KDF - the shared secret is SM9's own GM/T 0044.4 KDF output.
            spec = new KTSParameterSpec.Builder("Generic", 256).withNoKdf().build();
        }
        else if (!(spec instanceof KTSParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("SM9-KEM can only accept KTSParameterSpec");
        }
        else if (((KTSParameterSpec)spec).getKeyAlgorithmName() == null)
        {
            // SM9 sizes its secret from the spec itself and so does not go through
            // KdfUtil.resolveKemSpec, which rejects this for every other KEM: a null name would be
            // substituted for a "Generic" request and only fail deep inside the derivation.
            throw new InvalidAlgorithmParameterException("KTSParameterSpec has no key algorithm name");
        }

        return new SM9EncapsulatorSpi(bcPublicKey, (KTSParameterSpec)spec, secureRandom);
    }

    @Override
    public DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec)
        throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        if (!(privateKey instanceof BCSM9EncPrivateKey bcPrivateKey))
        {
            throw new InvalidKeyException("unsupported key type");
        }

        if (spec == null)
        {
            // No KDF - the shared secret is SM9's own GM/T 0044.4 KDF output.
            spec = new KTSParameterSpec.Builder("Generic", 256).withNoKdf().build();
        }
        else if (!(spec instanceof KTSParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("SM9-KEM can only accept KTSParameterSpec");
        }
        else if (((KTSParameterSpec)spec).getKeyAlgorithmName() == null)
        {
            // SM9 sizes its secret from the spec itself and so does not go through
            // KdfUtil.resolveKemSpec, which rejects this for every other KEM: a null name would be
            // substituted for a "Generic" request and only fail deep inside the derivation.
            throw new InvalidAlgorithmParameterException("KTSParameterSpec has no key algorithm name");
        }

        return new SM9DecapsulatorSpi(bcPrivateKey, (KTSParameterSpec)spec);
    }
}
