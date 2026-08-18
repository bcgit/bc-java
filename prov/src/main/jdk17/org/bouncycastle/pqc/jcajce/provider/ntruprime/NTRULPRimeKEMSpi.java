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
 * side by side for every other service, so this closes the registration gap between them.
 * <p>
 * As with the sibling, only a family level service is registered - NTRU LPRime's Cipher and
 * KeyGenerator registrations are family level too - so the single nested subclass is unrestricted.
 * The shape is kept so that acting on the "per-parameter-set SPI classes" note beside both
 * registrations needs no restructuring here.
 */
public abstract class NTRULPRimeKEMSpi
    implements KEMSpi
{
    private final NTRULPRimeParameters ntrulpRimeParameters;

    NTRULPRimeKEMSpi(NTRULPRimeParameters ntrulpRimeParameters)
    {
        this.ntrulpRimeParameters = ntrulpRimeParameters;
    }

    @Override
    public EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey, AlgorithmParameterSpec spec,
        SecureRandom secureRandom) throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        if (!(publicKey instanceof BCNTRULPRimePublicKey bcPublicKey))
        {
            throw new InvalidKeyException("unsupported key type");
        }

        checkKeyParameters(bcPublicKey.getKeyParams());

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

        checkKeyParameters(bcPrivateKey.getKeyParams());

        return new NTRULPRimeDecapsulatorSpi(bcPrivateKey, resolveSpec(spec, bcPrivateKey.getKeyParams()));
    }

    private static KTSParameterSpec resolveSpec(AlgorithmParameterSpec spec, NTRULPRimeKeyParameters key)
        throws InvalidAlgorithmParameterException
    {
        NTRULPRimeParameters keyParameters = key.getParameters();

        return KdfUtil.resolveKemSpec(spec, "NTRULPRime", keyParameters.getName(),
            keyParameters.getSessionKeySize());
    }

    private void checkKeyParameters(NTRULPRimeKeyParameters key) throws InvalidKeyException
    {
        if (ntrulpRimeParameters != null && ntrulpRimeParameters != key.getParameters())
        {
            throw new InvalidKeyException("NTRULPRime key mismatch");
        }
    }

    public static class NTRULPRime extends NTRULPRimeKEMSpi
    {
        public NTRULPRime()
        {
            // NOTE: Unrestricted parameters/keys
            super(null);
        }
    }
}
