package org.bouncycastle.pqc.jcajce.provider.ntruprime;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KEMSpi;

import org.bouncycastle.jcajce.provider.asymmetric.util.KdfUtil;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeKeyParameters;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeParameters;

/**
 * {@link javax.crypto.KEM} support for NTRU LPRime, registered as {@code KEM.NTRULPRIME}. Its
 * SNTRU Prime sibling has had this since the KEM API was first wired up; the two are registered
 * side by side for every other service, so this closes the one gap between them.
 * <p>
 * As with the sibling, the service is family level only - NTRU LPRime's Cipher and KeyGenerator
 * registrations are too, so there is no parameter-set locked variant to mirror.
 */
public class NTRULPRimeKEMSpi
    implements KEMSpi
{
    @Override
    public EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey, AlgorithmParameterSpec spec,
        SecureRandom secureRandom) throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        if (!(publicKey instanceof BCNTRULPRimePublicKey bcPublicKey))
        {
            throw new InvalidKeyException("unsupported key type");
        }

        return new NTRULPRimeEncapsulatorSpi(bcPublicKey, resolveSpec(spec, bcPublicKey.getKeyParams()),
            secureRandom);
    }

    @Override
    public DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec)
        throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        if (!(privateKey instanceof BCNTRULPRimePrivateKey bcPrivateKey))
        {
            throw new InvalidKeyException("unsupported key type");
        }

        return new NTRULPRimeDecapsulatorSpi(bcPrivateKey, resolveSpec(spec, bcPrivateKey.getKeyParams()));
    }

    private static KTSParameterSpec resolveSpec(AlgorithmParameterSpec spec, NTRULPRimeKeyParameters key)
        throws InvalidAlgorithmParameterException
    {
        NTRULPRimeParameters keyParameters = key.getParameters();

        return KdfUtil.resolveKemSpec(spec, "NTRULPRime", keyParameters.getName(),
            keyParameters.getSessionKeySize());
    }
}
