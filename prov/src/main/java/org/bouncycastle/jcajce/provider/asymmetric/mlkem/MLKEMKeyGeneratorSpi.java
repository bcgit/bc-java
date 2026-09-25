package org.bouncycastle.jcajce.provider.asymmetric.mlkem;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.kems.MLKEMExtractor;
import org.bouncycastle.crypto.kems.MLKEMGenerator;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.provider.asymmetric.util.KdfUtil;
import org.bouncycastle.jcajce.provider.util.SecurityExceptions;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.util.Arrays;

public class MLKEMKeyGeneratorSpi
    extends KeyGeneratorSpi
{
    private final MLKEMParameters mlkemParameters;
    
    private KEMGenerateSpec genSpec;
    private SecureRandom random;
    private KEMExtractSpec extSpec;
    private BCMLKEMPublicKey pubKey;
    private BCMLKEMPrivateKey privKey;

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
            KEMGenerateSpec spec = (KEMGenerateSpec)algorithmParameterSpec;
            BCMLKEMPublicKey key;
            try
            {
                key = Utils.toBCPublicKey(spec.getPublicKey());
            }
            catch (InvalidKeyException e)
            {
                throw SecurityExceptions.invalidAlgorithmParameterException(e.getMessage(), e);
            }
            if (mlkemParameters != null)
            {
                String canonicalAlgName = MLKEMParameterSpec.fromName(mlkemParameters.getName()).getName();
                if (!canonicalAlgName.equals(key.getAlgorithm()))
                {
                    throw new InvalidAlgorithmParameterException("key generator locked to " + canonicalAlgName);
                }
            }
            this.genSpec = spec;
            this.pubKey = key;
            this.extSpec = null;
            this.privKey = null;
        }
        else if (algorithmParameterSpec instanceof KEMExtractSpec)
        {
            KEMExtractSpec spec = (KEMExtractSpec)algorithmParameterSpec;
            BCMLKEMPrivateKey key;
            try
            {
                key = Utils.toBCPrivateKey(spec.getPrivateKey());
            }
            catch (InvalidKeyException e)
            {
                throw SecurityExceptions.invalidAlgorithmParameterException(e.getMessage(), e);
            }
            if (mlkemParameters != null)
            {
                String canonicalAlgName = MLKEMParameterSpec.fromName(mlkemParameters.getName()).getName();
                if (!canonicalAlgName.equals(key.getAlgorithm()))
                {
                    throw new InvalidAlgorithmParameterException("key generator locked to " + canonicalAlgName);
                }
            }
            this.genSpec = null;
            this.pubKey = null;
            this.extSpec = spec;
            this.privKey = key;
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
