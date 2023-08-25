package org.bouncycastle.pqc.jcajce.provider.kyber;

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
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMExtractor;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMGenerator;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public class KyberKeyGeneratorSpi
        extends KeyGeneratorSpi
{
    private KEMGenerateSpec genSpec;
    private SecureRandom random;
    private KEMExtractSpec extSpec;
    private KyberParameters kyberParameters;

    public KyberKeyGeneratorSpi()
    {
        this(null);
    }

    protected KyberKeyGeneratorSpi(KyberParameters kyberParameters)
    {
        this.kyberParameters = kyberParameters;
    }

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
            if (kyberParameters != null)
            {
                String canonicalAlgName = Strings.toUpperCase(kyberParameters.getName());
                if (!canonicalAlgName.equals(genSpec.getPublicKey().getAlgorithm()))
                {
                    throw new InvalidAlgorithmParameterException("key generator locked to " + canonicalAlgName);
                }
            }
        }
        else if (algorithmParameterSpec instanceof KEMExtractSpec)
        {
            this.genSpec = null;
            this.extSpec = (KEMExtractSpec)algorithmParameterSpec;
            if (kyberParameters != null)
            {
                String canonicalAlgName = Strings.toUpperCase(kyberParameters.getName());
                if (!canonicalAlgName.equals(extSpec.getPrivateKey().getAlgorithm()))
                {
                    throw new InvalidAlgorithmParameterException("key generator locked to " + canonicalAlgName);
                }
            }
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
            BCKyberPublicKey pubKey = (BCKyberPublicKey)genSpec.getPublicKey();
            KyberKEMGenerator kemGen = new KyberKEMGenerator(random);

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
            BCKyberPrivateKey privKey = (BCKyberPrivateKey)extSpec.getPrivateKey();
            KyberKEMExtractor kemExt = new KyberKEMExtractor(privKey.getKeyParams());

            byte[] encapsulation = extSpec.getEncapsulation();
            byte[] sharedSecret = kemExt.extractSecret(encapsulation);
            byte[] secret = Arrays.copyOfRange(sharedSecret, 0, (extSpec.getKeySize() + 7) / 8);

            Arrays.clear(sharedSecret);

            SecretKey rv = new SecretKeyWithEncapsulation(new SecretKeySpec(secret, extSpec.getKeyAlgorithmName()), encapsulation);

            Arrays.clear(secret);

            return rv;
        }
    }

    public static class Kyber512
        extends KyberKeyGeneratorSpi
    {
        public Kyber512()
        {
            super(KyberParameters.kyber512);
        }
    }

    public static class Kyber768
        extends KyberKeyGeneratorSpi
    {
        public Kyber768()
        {
            super(KyberParameters.kyber768);
        }
    }

    public static class Kyber1024
        extends KyberKeyGeneratorSpi
    {
        public Kyber1024()
        {
            super(KyberParameters.kyber1024);
        }
    }
}
