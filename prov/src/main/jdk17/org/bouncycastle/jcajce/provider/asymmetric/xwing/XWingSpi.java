package org.bouncycastle.jcajce.provider.asymmetric.xwing;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KEMSpi;

import org.bouncycastle.jcajce.provider.asymmetric.util.KdfUtil;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;

/**
 * {@link javax.crypto.KEM} support for X-Wing (draft-connolly-cfrg-xwing-kem), registered as {@code KEM.X-WING}.
 * <p>
 * With a null spec the shared secret is X-Wing's own 32-byte output - the interoperable form, and the one
 * the draft's HPKE and TLS uses expect. A {@link KTSParameterSpec} KDF may optionally be layered on top.
 */
public class XWingSpi
    implements KEMSpi
{
    public XWingSpi()
    {
    }

    @Override
    public EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey, AlgorithmParameterSpec spec,
        SecureRandom secureRandom) throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        if (!(publicKey instanceof BCXWingPublicKey bcPublicKey))
        {
            throw new InvalidKeyException("unsupported key type");
        }

        return new XWingEncapsulatorSpi(bcPublicKey, resolveSpec(spec), secureRandom);
    }

    @Override
    public DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec)
        throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        if (!(privateKey instanceof BCXWingPrivateKey bcPrivateKey))
        {
            throw new InvalidKeyException("unsupported key type");
        }

        return new XWingDecapsulatorSpi(bcPrivateKey, resolveSpec(spec));
    }

    private static KTSParameterSpec resolveSpec(AlgorithmParameterSpec spec)
        throws InvalidAlgorithmParameterException
    {
        return KdfUtil.resolveKemSpec(spec, "X-Wing", "X-Wing", 256);
    }
}
