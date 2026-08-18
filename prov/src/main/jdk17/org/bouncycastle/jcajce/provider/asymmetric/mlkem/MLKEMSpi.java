package org.bouncycastle.jcajce.provider.asymmetric.mlkem;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KEMSpi;

import org.bouncycastle.jcajce.provider.asymmetric.util.KdfUtil;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.crypto.params.MLKEMKeyParameters;
import org.bouncycastle.crypto.params.MLKEMParameters;

public abstract class MLKEMSpi
    implements KEMSpi
{
    private final MLKEMParameters mlkemParameters;

    MLKEMSpi(MLKEMParameters mlkemParameters)
    {
        this.mlkemParameters = mlkemParameters;
    }

    @Override
    public EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey, AlgorithmParameterSpec spec,
        SecureRandom secureRandom) throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        if (!(publicKey instanceof BCMLKEMPublicKey bcPublicKey))
        {
            throw new InvalidKeyException("unsupported key type");
        }

        checkKeyParameters(bcPublicKey.getKeyParams());


        return new MLKEMEncapsulatorSpi(bcPublicKey,
            resolveSpec(spec, bcPublicKey.getKeyParams()), secureRandom);
    }

    @Override
    public DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec)
        throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        if (!(privateKey instanceof BCMLKEMPrivateKey bcPrivateKey))
        {
            throw new InvalidKeyException("unsupported key type");
        }

        checkKeyParameters(bcPrivateKey.getKeyParams());


        return new MLKEMDecapsulatorSpi(bcPrivateKey, resolveSpec(spec, bcPrivateKey.getKeyParams()));
    }

    private static KTSParameterSpec resolveSpec(AlgorithmParameterSpec spec, MLKEMKeyParameters key)
        throws InvalidAlgorithmParameterException
    {
        MLKEMParameters keyParameters = key.getParameters();

        return KdfUtil.resolveKemSpec(spec, "ML-KEM", keyParameters.getName(),
            keyParameters.getSessionKeySize());
    }

    private void checkKeyParameters(MLKEMKeyParameters key) throws InvalidKeyException
    {
        if (mlkemParameters != null && mlkemParameters != key.getParameters())
        {
            throw new InvalidKeyException("ML-KEM key mismatch");
        }
    }

    public static class MLKEM extends MLKEMSpi
    {
        public MLKEM()
        {
            // NOTE: Unrestricted parameters/keys
            super(null);
        }
    }

    public static class MLKEM512 extends MLKEMSpi
    {
        public MLKEM512()
        {
            super(MLKEMParameters.ml_kem_512);
        }
    }

    public static class MLKEM768 extends MLKEMSpi
    {
        public MLKEM768()
        {
            super(MLKEMParameters.ml_kem_768);
        }
    }

    public static class MLKEM1024 extends MLKEMSpi
    {
        public MLKEM1024()
        {
            super(MLKEMParameters.ml_kem_1024);
        }
    }
}
