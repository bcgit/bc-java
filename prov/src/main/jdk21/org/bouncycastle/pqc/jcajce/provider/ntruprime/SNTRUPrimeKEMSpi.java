package org.bouncycastle.pqc.jcajce.provider.ntruprime;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKEMGenerator;
import org.bouncycastle.pqc.jcajce.provider.util.WrapUtil;
import org.bouncycastle.util.Arrays;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KEMSpi;
import javax.security.auth.DestroyFailedException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class SNTRUPrimeKEMSpi
    implements KEMSpi
{

    @Override
    public EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey, AlgorithmParameterSpec spec, SecureRandom secureRandom) throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        if (!(publicKey instanceof BCSNTRUPrimePublicKey))
        {
            throw new InvalidKeyException("unsupported key");
        }
        if (spec == null)
        {
            // TODO: default should probably use shake.
            spec = new KTSParameterSpec.Builder("AES-KWP", 256).build();
        }
        if (!(spec instanceof KTSParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("SNTRUPrime can only accept KTSParameterSpec");
        }
        if (secureRandom == null)
        {
            secureRandom = new SecureRandom();
        }
        return new SNTRUPrimeEncapsulatorSpi((BCSNTRUPrimePublicKey) publicKey,(KTSParameterSpec) spec, secureRandom);
    }

    @Override
    public DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec) throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        if (!(privateKey instanceof BCSNTRUPrimePrivateKey))
        {
            throw new InvalidKeyException("unsupported key");
        }
        if (spec == null)
        {
            // TODO: default should probably use shake.
            spec = new KTSParameterSpec.Builder("AES-KWP", 256).build();
        }
        if (!(spec instanceof KTSParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("SNTRUPrime can only accept KTSParameterSpec");
        }
        return new SNTRUPrimeDecapsulatorSpi((BCSNTRUPrimePrivateKey) privateKey, (KTSParameterSpec) spec);
    }
}
