package org.bouncycastle.jcajce.provider.asymmetric.mlkem;

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
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.jcajce.provider.util.KdfUtil;
import org.bouncycastle.util.Arrays;

public class MLKEMKeyGeneratorSpi
    extends KeyGeneratorSpi
{
    private final MLKEMParameters mlkemParameters;

    private KEMGenerateSpec genSpec;
    private SecureRandom random;
    private KEMExtractSpec extSpec;

    public MLKEMKeyGeneratorSpi()
    {
        this(null);
    }

    protected MLKEMKeyGeneratorSpi(MLKEMParameters mlkemParameters)
    {
        this.mlkemParameters = mlkemParameters;
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
            if (mlkemParameters != null)
            {
                String canonicalAlgName = MLKEMParameterSpec.fromName(mlkemParameters.getName()).getName();
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
            if (mlkemParameters != null)
            {
                String canonicalAlgName = MLKEMParameterSpec.fromName(mlkemParameters.getName()).getName();
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
            BCMLKEMPublicKey pubKey = (BCMLKEMPublicKey)genSpec.getPublicKey();
            MLKEMGenerator kemGen = new MLKEMGenerator(random);

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
            BCMLKEMPrivateKey privKey = (BCMLKEMPrivateKey)extSpec.getPrivateKey();
            MLKEMExtractor kemExt = new MLKEMExtractor(privKey.getKeyParams());

            byte[] encapsulation = extSpec.getEncapsulation();

            byte[] kemSecret = kemExt.extractSecret(encapsulation);
            byte[] kdfSecret = KdfUtil.makeKeyBytes(extSpec, kemSecret);

            try
            {
                SecretKeySpec secretKey = new SecretKeySpec(kdfSecret, extSpec.getKeyAlgorithmName());

                // TODO Why do we return ...WithEncapsulation?? 
                return new SecretKeyWithEncapsulation(secretKey, encapsulation);
            }
            finally
            {
                Arrays.clear(kdfSecret);
            }
        }
    }

    public static class MLKEM512
        extends MLKEMKeyGeneratorSpi
    {
        public MLKEM512()
        {
            super(MLKEMParameters.ml_kem_512);
        }
    }

    public static class MLKEM768
        extends MLKEMKeyGeneratorSpi
    {
        public MLKEM768()
        {
            super(MLKEMParameters.ml_kem_768);
        }
    }

    public static class MLKEM1024
        extends MLKEMKeyGeneratorSpi
    {
        public MLKEM1024()
        {
            super(MLKEMParameters.ml_kem_1024);
        }
    }
}
