package org.bouncycastle.pqc.jcajce.provider.hqc;

import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.provider.asymmetric.util.KdfUtil;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.KEMKDFSpec;
import org.bouncycastle.pqc.crypto.hqc.HQCKEMExtractor;
import org.bouncycastle.pqc.crypto.hqc.HQCKEMGenerator;
import org.bouncycastle.pqc.crypto.hqc.HQCParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.util.Strings;

public class HQCKeyGeneratorSpi
    extends KeyGeneratorSpi
{
    private KEMGenerateSpec genSpec;
    private SecureRandom random;
    private KEMExtractSpec extSpec;
    private HQCParameters hqcParameters;

    public HQCKeyGeneratorSpi()
    {
        this(null);
    }

    public HQCKeyGeneratorSpi(HQCParameters hqcParameters)
    {
        this.hqcParameters = hqcParameters;
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
            checkSpec((KEMGenerateSpec)algorithmParameterSpec, ((KEMGenerateSpec)algorithmParameterSpec).getPublicKey());
            this.genSpec = (KEMGenerateSpec)algorithmParameterSpec;
            this.extSpec = null;
            if (hqcParameters != null)
            {
                String canonicalAlgName = Strings.toUpperCase(hqcParameters.getName());
                if (!canonicalAlgName.equals(genSpec.getPublicKey().getAlgorithm()))
                {
                    throw new InvalidAlgorithmParameterException("key generator locked to " + canonicalAlgName);
                }
            }
        }
        else if (algorithmParameterSpec instanceof KEMExtractSpec)
        {
            this.genSpec = null;
            checkSpec((KEMExtractSpec)algorithmParameterSpec, ((KEMExtractSpec)algorithmParameterSpec).getPrivateKey());
            this.extSpec = (KEMExtractSpec)algorithmParameterSpec;
            if (hqcParameters != null)
            {
                String canonicalAlgName = Strings.toUpperCase(hqcParameters.getName());
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

    // the key's parameter set gives the size of the shared secret a spec with no KDF is limited to
    private static void checkSpec(KEMKDFSpec spec, Key key)
        throws InvalidAlgorithmParameterException
    {
        HQCParameters parameters;
        if (key instanceof BCHQCPublicKey)
        {
            parameters = ((BCHQCPublicKey)key).getKeyParams().getParameters();
        }
        else if (key instanceof BCHQCPrivateKey)
        {
            parameters = ((BCHQCPrivateKey)key).getKeyParams().getParameters();
        }
        else
        {
            throw new InvalidAlgorithmParameterException("unsupported key: HQC key required");
        }

        KdfUtil.checkKemKdfSpec(spec, parameters.getName(), parameters.getSessionKeySize());
    }

    protected SecretKey engineGenerateKey()
    {
        if (genSpec != null)
        {
            BCHQCPublicKey pubKey = (BCHQCPublicKey)genSpec.getPublicKey();
            HQCKEMGenerator kemGen = new HQCKEMGenerator(random);

            SecretWithEncapsulation secEnc = kemGen.generateEncapsulated(pubKey.getKeyParams());

            byte[] keyBytes = KdfUtil.makeKeyBytes(genSpec, secEnc.getSecret());

            SecretKey rv = new SecretKeyWithEncapsulation(new SecretKeySpec(keyBytes, genSpec.getKeyAlgorithmName()), secEnc.getEncapsulation());

            Arrays.clear(keyBytes);

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
            BCHQCPrivateKey privKey = (BCHQCPrivateKey)extSpec.getPrivateKey();
            HQCKEMExtractor kemExt = new HQCKEMExtractor(privKey.getKeyParams());

            byte[] encapsulation = extSpec.getEncapsulation();
            byte[] secret = kemExt.extractSecret(encapsulation);

            byte[] keyBytes = KdfUtil.makeKeyBytes(extSpec, secret);

            SecretKey rv = new SecretKeyWithEncapsulation(new SecretKeySpec(keyBytes, extSpec.getKeyAlgorithmName()), encapsulation);

            Arrays.clear(keyBytes);

            return rv;
        }
    }

    public static class HQC128
        extends HQCKeyGeneratorSpi
    {
        public HQC128()
        {
            super(HQCParameters.hqc128);
        }
    }

    public static class HQC192
        extends HQCKeyGeneratorSpi
    {
        public HQC192()
        {
            super(HQCParameters.hqc192);
        }
    }

    public static class HQC256
        extends HQCKeyGeneratorSpi
    {
        public HQC256()
        {
            super(HQCParameters.hqc256);
        }
    }
}
