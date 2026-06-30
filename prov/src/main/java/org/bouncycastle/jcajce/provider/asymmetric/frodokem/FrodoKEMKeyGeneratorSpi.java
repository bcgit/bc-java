package org.bouncycastle.jcajce.provider.asymmetric.frodokem;

import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.kems.FrodoKEMExtractor;
import org.bouncycastle.crypto.kems.FrodoKEMGenerator;
import org.bouncycastle.crypto.params.FrodoKEMParameters;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.provider.asymmetric.util.KdfUtil;
import org.bouncycastle.jcajce.spec.FrodoKEMParameterSpec;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.util.Arrays;

public class FrodoKEMKeyGeneratorSpi
    extends KeyGeneratorSpi
{
    private final FrodoKEMParameters frodoKEMParameters;

    private KEMGenerateSpec genSpec;
    private SecureRandom random;
    private KEMExtractSpec extSpec;

    public FrodoKEMKeyGeneratorSpi()
    {
        this(null);
    }

    protected FrodoKEMKeyGeneratorSpi(FrodoKEMParameters frodoKEMParameters)
    {
        this.frodoKEMParameters = frodoKEMParameters;
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
            if (frodoKEMParameters != null)
            {
                String canonicalAlgName = FrodoKEMParameterSpec.fromName(frodoKEMParameters.getName()).getName();
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
            if (frodoKEMParameters != null)
            {
                String canonicalAlgName = FrodoKEMParameterSpec.fromName(frodoKEMParameters.getName()).getName();
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
            BCFrodoKEMPublicKey pubKey = (BCFrodoKEMPublicKey)genSpec.getPublicKey();
            FrodoKEMGenerator kemGen = new FrodoKEMGenerator(random);

            SecretWithEncapsulation secEnc = kemGen.generateEncapsulated(pubKey.getKeyParams());

            byte[] kemSecret = secEnc.getSecret();
            byte[] kdfSecret = KdfUtil.makeKeyBytes(genSpec, kemSecret);

            try
            {
                SecretKeySpec secretKey = new SecretKeySpec(kdfSecret, genSpec.getKeyAlgorithmName());

                return new SecretKeyWithEncapsulation(secretKey, secEnc.getEncapsulation());
            }
            finally
            {
                try
                {
                    secEnc.destroy();
                }
                catch (DestroyFailedException e)
                {
                    // ignore
                }
            }
        }
        else
        {
            BCFrodoKEMPrivateKey privKey = (BCFrodoKEMPrivateKey)extSpec.getPrivateKey();
            FrodoKEMExtractor kemExt = new FrodoKEMExtractor(privKey.getKeyParams());

            byte[] encapsulation = extSpec.getEncapsulation();

            byte[] kemSecret = kemExt.extractSecret(encapsulation);
            byte[] kdfSecret = KdfUtil.makeKeyBytes(extSpec, kemSecret);

            try
            {
                SecretKeySpec secretKey = new SecretKeySpec(kdfSecret, extSpec.getKeyAlgorithmName());

                return new SecretKeyWithEncapsulation(secretKey, encapsulation);
            }
            finally
            {
                Arrays.clear(kdfSecret);
            }
        }
    }

    public static class Frodokem976Shake
        extends FrodoKEMKeyGeneratorSpi
    {
        public Frodokem976Shake()
        {
            super(FrodoKEMParameters.frodokem976shake);
        }
    }

    public static class Frodokem1344Shake
        extends FrodoKEMKeyGeneratorSpi
    {
        public Frodokem1344Shake()
        {
            super(FrodoKEMParameters.frodokem1344shake);
        }
    }

    public static class EFrodokem976Shake
        extends FrodoKEMKeyGeneratorSpi
    {
        public EFrodokem976Shake()
        {
            super(FrodoKEMParameters.efrodokem976shake);
        }
    }

    public static class EFrodokem1344Shake
        extends FrodoKEMKeyGeneratorSpi
    {
        public EFrodokem1344Shake()
        {
            super(FrodoKEMParameters.efrodokem1344shake);
        }
    }

    public static class Frodokem976Aes
        extends FrodoKEMKeyGeneratorSpi
    {
        public Frodokem976Aes()
        {
            super(FrodoKEMParameters.frodokem976aes);
        }
    }

    public static class Frodokem1344Aes
        extends FrodoKEMKeyGeneratorSpi
    {
        public Frodokem1344Aes()
        {
            super(FrodoKEMParameters.frodokem1344aes);
        }
    }

    public static class EFrodokem976Aes
        extends FrodoKEMKeyGeneratorSpi
    {
        public EFrodokem976Aes()
        {
            super(FrodoKEMParameters.efrodokem976aes);
        }
    }

    public static class EFrodokem1344Aes
        extends FrodoKEMKeyGeneratorSpi
    {
        public EFrodokem1344Aes()
        {
            super(FrodoKEMParameters.efrodokem1344aes);
        }
    }
}
