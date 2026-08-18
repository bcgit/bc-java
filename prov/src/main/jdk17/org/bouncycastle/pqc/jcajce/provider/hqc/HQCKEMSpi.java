package org.bouncycastle.pqc.jcajce.provider.hqc;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KEMSpi;

import org.bouncycastle.jcajce.provider.asymmetric.util.KdfUtil;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.pqc.crypto.hqc.HQCKeyParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCParameters;

public abstract class HQCKEMSpi
    implements KEMSpi
{
    private final HQCParameters hqcParameters;

    HQCKEMSpi(HQCParameters hqcParameters)
    {
        this.hqcParameters = hqcParameters;
    }

    @Override
    public EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey, AlgorithmParameterSpec spec,
        SecureRandom secureRandom) throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        if (!(publicKey instanceof BCHQCPublicKey bcPublicKey))
        {
            throw new InvalidKeyException("unsupported key type");
        }

        checkKeyParameters(bcPublicKey.getKeyParams());


        return new HQCEncapsulatorSpi(bcPublicKey,
            resolveSpec(spec, bcPublicKey.getKeyParams()), secureRandom);
    }

    @Override
    public DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec)
        throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        if (!(privateKey instanceof BCHQCPrivateKey bcPrivateKey))
        {
            throw new InvalidKeyException("unsupported key type");
        }

        checkKeyParameters(bcPrivateKey.getKeyParams());


        return new HQCDecapsulatorSpi(bcPrivateKey, resolveSpec(spec, bcPrivateKey.getKeyParams()));
    }

    private static KTSParameterSpec resolveSpec(AlgorithmParameterSpec spec, HQCKeyParameters key)
        throws InvalidAlgorithmParameterException
    {
        HQCParameters keyParameters = key.getParameters();

        return KdfUtil.resolveKemSpec(spec, "HQC", keyParameters.getName(),
            keyParameters.getSessionKeySize());
    }

    private void checkKeyParameters(HQCKeyParameters key) throws InvalidKeyException
    {
        if (hqcParameters != null && hqcParameters != key.getParameters())
        {
            throw new InvalidKeyException("HQC key mismatch");
        }
    }

    public static class HQC extends HQCKEMSpi
    {
        public HQC()
        {
            // NOTE: Unrestricted parameters/keys
            super(null);
        }
    }

    public static class HQC128 extends HQCKEMSpi
    {
        public HQC128()
        {
            super(HQCParameters.hqc128);
        }
    }

    public static class HQC192 extends HQCKEMSpi
    {
        public HQC192()
        {
            super(HQCParameters.hqc192);
        }
    }

    public static class HQC256 extends HQCKEMSpi
    {
        public HQC256()
        {
            super(HQCParameters.hqc256);
        }
    }
}
