package org.bouncycastle.jcajce.provider.asymmetric.mlkem;

import org.bouncycastle.jcajce.provider.asymmetric.mlkem.BCMLKEMPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.mlkem.BCMLKEMPublicKey;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;

import javax.crypto.KEMSpi;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class MLKEMSpi
    implements KEMSpi
{
    @Override
    public EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey, AlgorithmParameterSpec spec, SecureRandom secureRandom)
            throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        if (!(publicKey instanceof BCMLKEMPublicKey))
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
            throw new InvalidAlgorithmParameterException("MLKEM can only accept KTSParameterSpec");
        }
        if (secureRandom == null)
        {
            secureRandom = new SecureRandom();
        }
        return new MLKEMEncapsulatorSpi((BCMLKEMPublicKey) publicKey, (KTSParameterSpec) spec, secureRandom);
    }

    @Override
    public DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec)
            throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        if (!(privateKey instanceof BCMLKEMPrivateKey))
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
            throw new InvalidAlgorithmParameterException("MLKEM can only accept KTSParameterSpec");
        }
        return new MLKEMDecapsulatorSpi((BCMLKEMPrivateKey) privateKey, (KTSParameterSpec) spec);
    }
}
