package org.bouncycastle.pqc.jcajce.provider.ntru;

import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.pqc.crypto.ntru.NTRUKEMExtractor;
import org.bouncycastle.pqc.crypto.ntru.NTRUKEMGenerator;
import org.bouncycastle.util.Arrays;

public class NTRUKeyGeneratorSpi
        extends KeyGeneratorSpi
{
    private KEMGenerateSpec genSpec;
    private SecureRandom random;
    private KEMExtractSpec extSpec;

    protected void engineInit(SecureRandom secureRandom)
    {
        throw new UnsupportedOperationException("Operation not supported");
    }

    protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom)
            throws InvalidAlgorithmParameterException
    {
        this.random = secureRandom;
        if (algorithmParameterSpec instanceof KEMGenerateSpec)
        {
            this.genSpec = (KEMGenerateSpec)algorithmParameterSpec;
            this.extSpec = null;
        }
        else if (algorithmParameterSpec instanceof KEMExtractSpec)
        {
            this.genSpec = null;
            this.extSpec = (KEMExtractSpec)algorithmParameterSpec;
        }
        else
        {
            throw new InvalidAlgorithmParameterException("unknown spec");
        }
    }

    protected void engineInit(int i, SecureRandom secureRandom)
    {
        throw new UnsupportedOperationException("Operation not supported");
    }

    protected SecretKey engineGenerateKey()
    {
        if (genSpec != null)
        {
            BCNTRUPublicKey pubKey = (BCNTRUPublicKey)genSpec.getPublicKey();
            NTRUKEMGenerator kemGen = new NTRUKEMGenerator(random);

            SecretWithEncapsulation secEnc = kemGen.generateEncapsulated(pubKey.getKeyParams());

            byte[] sharedSecret = secEnc.getSecret();
            byte[] secret = Arrays.copyOfRange(sharedSecret, 0, (genSpec.getKeySize() + 7) / 8);

            Arrays.clear(sharedSecret);

            SecretKey rv = new SecretKeyWithEncapsulation(new SecretKeySpec(secret, genSpec.getKeyAlgorithmName()), secEnc.getEncapsulation());

            try
            {
                secEnc.destroy();
            }
            catch (DestroyFailedException e)
            {
                throw new IllegalStateException("key cleanup failed");
            }

            return rv;
        }
        else
        {
            BCNTRUPrivateKey privKey = (BCNTRUPrivateKey)extSpec.getPrivateKey();
            NTRUKEMExtractor kemExt = new NTRUKEMExtractor(privKey.getKeyParams());

            byte[] encapsulation = extSpec.getEncapsulation();
            byte[] sharedSecret = kemExt.extractSecret(encapsulation);
            byte[] secret = Arrays.copyOfRange(sharedSecret, 0, (extSpec.getKeySize() + 7) / 8);

            Arrays.clear(sharedSecret);

            SecretKey rv = new SecretKeyWithEncapsulation(new SecretKeySpec(secret, extSpec.getKeyAlgorithmName()), encapsulation);

            Arrays.clear(secret);

            return rv;
        }
    }
}
