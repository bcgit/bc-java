package org.bouncycastle.pqc.jcajce.provider.smaugt;

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
import org.bouncycastle.pqc.crypto.smaugt.SmaugTKEMExtractor;
import org.bouncycastle.pqc.crypto.smaugt.SmaugTKEMGenerator;
import org.bouncycastle.pqc.crypto.smaugt.SmaugTParameters;
import org.bouncycastle.pqc.jcajce.spec.SmaugTParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;

public class SmaugTKeyGeneratorSpi
    extends KeyGeneratorSpi
{
    private KEMGenerateSpec genSpec;
    private SecureRandom random;
    private KEMExtractSpec extSpec;
    private SmaugTParameters smaugTParameters;

    public SmaugTKeyGeneratorSpi()
    {
        this(null);
    }

    public SmaugTKeyGeneratorSpi(SmaugTParameters smaugTParameters)
    {
        this.smaugTParameters = smaugTParameters;
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
            if (smaugTParameters != null)
            {
                String canonicalAlgName = SmaugTParameterSpec.fromName(smaugTParameters.getName()).getName();
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
            if (smaugTParameters != null)
            {
                String canonicalAlgName = SmaugTParameterSpec.fromName(smaugTParameters.getName()).getName();
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
            BCSmaugTPublicKey pubKey = (BCSmaugTPublicKey)genSpec.getPublicKey();
            SmaugTKEMGenerator kemGen = new SmaugTKEMGenerator(random);

            SecretWithEncapsulation secEnc = kemGen.generateEncapsulated(pubKey.getKeyParams());

            SecretKey rv = new SecretKeyWithEncapsulation(new SecretKeySpec(secEnc.getSecret(), genSpec.getKeyAlgorithmName()), secEnc.getEncapsulation());

            try
            {
                secEnc.destroy();
            }
            catch (DestroyFailedException e)
            {
                throw Exceptions.illegalStateException("key cleanup failed", e);
            }

            return rv;
        }
        else
        {
            BCSmaugTPrivateKey privKey = (BCSmaugTPrivateKey)extSpec.getPrivateKey();
            SmaugTKEMExtractor kemExt = new SmaugTKEMExtractor(privKey.getKeyParams());

            byte[] encapsulation = extSpec.getEncapsulation();
            byte[] secret = kemExt.extractSecret(encapsulation);

            SecretKey rv = new SecretKeyWithEncapsulation(new SecretKeySpec(secret, extSpec.getKeyAlgorithmName()), encapsulation);

            Arrays.clear(secret);

            return rv;
        }
    }

    public static class Mode1
        extends SmaugTKeyGeneratorSpi
    {
        public Mode1()
        {
            super(SmaugTParameters.smaugt_mode1);
        }
    }

    public static class Mode3
        extends SmaugTKeyGeneratorSpi
    {
        public Mode3()
        {
            super(SmaugTParameters.smaugt_mode3);
        }
    }

    public static class Mode5
        extends SmaugTKeyGeneratorSpi
    {
        public Mode5()
        {
            super(SmaugTParameters.smaugt_mode5);
        }
    }

    public static class ModeT
        extends SmaugTKeyGeneratorSpi
    {
        public ModeT()
        {
            super(SmaugTParameters.smaugt_modet);
        }
    }
}
