package org.bouncycastle.pqc.jcajce.provider.hqc;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KEMSpi;

import org.bouncycastle.jcajce.spec.KTSParameterSpec;

public class HQCKEMSpi
    implements KEMSpi
{

    @Override
    public EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey, AlgorithmParameterSpec spec,
                                                 SecureRandom secureRandom)
        throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        if (!(publicKey instanceof BCHQCPublicKey))
        {
            throw new InvalidKeyException("unsupported key");
        }
        if (spec == null)
        {
            // Do not wrap key, no KDF
            spec = new KTSParameterSpec.Builder("Generic", 256).withNoKdf().build();
        }
        if (!(spec instanceof KTSParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("HQC can only accept KTSParameterSpec");
        }
        if (secureRandom == null)
        {
            secureRandom = new SecureRandom();
        }
        return new HQCEncapsulatorSpi((BCHQCPublicKey)publicKey, (KTSParameterSpec)spec, secureRandom);
    }

    @Override
    public DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec)
        throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        if (!(privateKey instanceof BCHQCPrivateKey))
        {
            throw new InvalidKeyException("unsupported key");
        }
        if (spec == null)
        {
            // Do not unwrap key, no KDF
            spec = new KTSParameterSpec.Builder("Generic", 256).withNoKdf().build();
        }
        if (!(spec instanceof KTSParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("HQC can only accept KTSParameterSpec");
        }
        return new HQCDecapsulatorSpi((BCHQCPrivateKey)privateKey, (KTSParameterSpec)spec);
    }
}