package org.bouncycastle.jcajce.provider.asymmetric.mlkem;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KEMSpi;

import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;

public class MLKEMSpi
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
        if (!(publicKey instanceof BCMLKEMPublicKey))
        {
            throw new InvalidKeyException("unsupported key type");
        }

        BCMLKEMPublicKey bcPublicKey = (BCMLKEMPublicKey)publicKey;
        checkKeyParameters(bcPublicKey.getKeyParams());

        if (spec == null)
        {
            // Do not wrap key, no KDF
            spec = new KTSParameterSpec.Builder("Generic", 256).withNoKdf().build();
        }
        else if (!(spec instanceof KTSParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("MLKEM can only accept KTSParameterSpec");
        }

        return new MLKEMEncapsulatorSpi(bcPublicKey, (KTSParameterSpec)spec, secureRandom);
    }

    @Override
    public DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec)
        throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        if (!(privateKey instanceof BCMLKEMPrivateKey))
        {
            throw new InvalidKeyException("unsupported key");
        }

        BCMLKEMPrivateKey bcPrivateKey = (BCMLKEMPrivateKey)privateKey;
        checkKeyParameters(bcPrivateKey.getKeyParams());

        if (spec == null)
        {
            // Do not unwrap key, no KDF
            spec = new KTSParameterSpec.Builder("Generic", 256).withNoKdf().build();
        }
        else if (!(spec instanceof KTSParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("MLKEM can only accept KTSParameterSpec");
        }

        return new MLKEMDecapsulatorSpi(bcPrivateKey, (KTSParameterSpec)spec);
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
