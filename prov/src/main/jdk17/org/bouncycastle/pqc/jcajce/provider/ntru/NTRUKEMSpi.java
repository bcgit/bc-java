package org.bouncycastle.pqc.jcajce.provider.ntru;

import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.pqc.jcajce.provider.ntru.BCNTRUPrivateKey;
import org.bouncycastle.pqc.jcajce.provider.ntru.NTRUDecapsulatorSpi;

import javax.crypto.KEMSpi;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class NTRUKEMSpi
    implements KEMSpi
{

    @Override
    public EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey, AlgorithmParameterSpec spec, SecureRandom secureRandom)
            throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        if (!(publicKey instanceof BCNTRUPublicKey))
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
            throw new InvalidAlgorithmParameterException("NTRU can only accept KTSParameterSpec");
        }
        if (secureRandom == null)
        {
            secureRandom = new SecureRandom();
        }
        return new NTRUEncapsulatorSpi((BCNTRUPublicKey) publicKey, (KTSParameterSpec) spec, secureRandom);
    }

    @Override
    public DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec)
            throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        if (!(privateKey instanceof BCNTRUPrivateKey))
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
            throw new InvalidAlgorithmParameterException("NTRU can only accept KTSParameterSpec");
        }
        return new NTRUDecapsulatorSpi((BCNTRUPrivateKey) privateKey, (KTSParameterSpec) spec);
    }
}
