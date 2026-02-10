package org.bouncycastle.pqc.jcajce.provider.hqc;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KEMSpi;

import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.pqc.crypto.hqc.HQCKeyParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCParameters;

public class HQCKEMSpi
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

        if (spec == null)
        {
            // Do not wrap key, no KDF
            spec = new KTSParameterSpec.Builder("Generic", 256).withNoKdf().build();
        }
        else if (!(spec instanceof KTSParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("HQC can only accept KTSParameterSpec");
        }

        return new HQCEncapsulatorSpi(bcPublicKey, (KTSParameterSpec)spec, secureRandom);
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

        if (spec == null)
        {
            // Do not unwrap key, no KDF
            spec = new KTSParameterSpec.Builder("Generic", 256).withNoKdf().build();
        }
        else if (!(spec instanceof KTSParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("HQC can only accept KTSParameterSpec");
        }

        return new HQCDecapsulatorSpi(bcPrivateKey, (KTSParameterSpec)spec);
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
