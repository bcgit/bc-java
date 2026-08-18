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
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKeyParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeParameters;

public abstract class SNTRUPrimeKEMSpi
    implements KEMSpi
{
    private final SNTRUPrimeParameters sntruPrimeParameters;

    SNTRUPrimeKEMSpi(SNTRUPrimeParameters sntruPrimeParameters)
    {
        this.sntruPrimeParameters = sntruPrimeParameters;
    }

    @Override
    public EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey, AlgorithmParameterSpec spec,
        SecureRandom secureRandom) throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        if (!(publicKey instanceof BCSNTRUPrimePublicKey bcPublicKey))
        {
            throw new InvalidKeyException("unsupported key type");
        }

        checkKeyParameters(bcPublicKey.getKeyParams());


        return new SNTRUPrimeEncapsulatorSpi(bcPublicKey,
            resolveSpec(spec, bcPublicKey.getKeyParams()), secureRandom);
    }

    @Override
    public DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec)
        throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        if (!(privateKey instanceof BCSNTRUPrimePrivateKey bcPrivateKey))
        {
            throw new InvalidKeyException("unsupported key type");
        }

        checkKeyParameters(bcPrivateKey.getKeyParams());


        return new SNTRUPrimeDecapsulatorSpi(bcPrivateKey, resolveSpec(spec, bcPrivateKey.getKeyParams()));
    }

    private static KTSParameterSpec resolveSpec(AlgorithmParameterSpec spec, SNTRUPrimeKeyParameters key)
        throws InvalidAlgorithmParameterException
    {
        SNTRUPrimeParameters keyParameters = key.getParameters();

        return KdfUtil.resolveKemSpec(spec, "SNTRUPrime", keyParameters.getName(),
            keyParameters.getSessionKeySize());
    }

    private void checkKeyParameters(SNTRUPrimeKeyParameters key) throws InvalidKeyException
    {
        if (sntruPrimeParameters != null && sntruPrimeParameters != key.getParameters())
        {
            throw new InvalidKeyException("SNTRUPrime key mismatch");
        }
    }

    public static class SNTRUPrime extends SNTRUPrimeKEMSpi
    {
        public SNTRUPrime()
        {
            // NOTE: Unrestricted parameters/keys
            super(null);
        }
    }
}
