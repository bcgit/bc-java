package org.bouncycastle.pqc.jcajce.provider.ntruplus;

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
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusKEMExtractor;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusKEMGenerator;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.util.Strings;

public class NTRUPlusKeyGeneratorSpi
    extends KeyGeneratorSpi
{
    private KEMGenerateSpec genSpec;
    private SecureRandom random;
    private KEMExtractSpec extSpec;
    private NTRUPlusParameters ntruplusParameters;

    public NTRUPlusKeyGeneratorSpi()
    {
        this(null);
    }

    public NTRUPlusKeyGeneratorSpi(NTRUPlusParameters ntruplusParameters)
    {
        this.ntruplusParameters = ntruplusParameters;
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
            if (ntruplusParameters != null)
            {
                String canonicalAlgName = Strings.toUpperCase(ntruplusParameters.getName());
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
            if (ntruplusParameters != null)
            {
                String canonicalAlgName = Strings.toUpperCase(ntruplusParameters.getName());
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
        NTRUPlusParameters parameters;
        if (key instanceof BCNTRUPlusPublicKey)
        {
            parameters = ((BCNTRUPlusPublicKey)key).getKeyParams().getParameters();
        }
        else if (key instanceof BCNTRUPlusPrivateKey)
        {
            parameters = ((BCNTRUPlusPrivateKey)key).getKeyParams().getParameters();
        }
        else
        {
            throw new InvalidAlgorithmParameterException("unsupported key: NTRU+ key required");
        }

        KdfUtil.checkKemKdfSpec(spec, parameters.getName(), parameters.getSsBytes() * 8);
    }

    protected SecretKey engineGenerateKey()
    {
        if (genSpec != null)
        {
            BCNTRUPlusPublicKey pubKey = (BCNTRUPlusPublicKey)genSpec.getPublicKey();
            NTRUPlusKEMGenerator kemGen = new NTRUPlusKEMGenerator(random);

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
            BCNTRUPlusPrivateKey privKey = (BCNTRUPlusPrivateKey)extSpec.getPrivateKey();
            NTRUPlusKEMExtractor kemExt = new NTRUPlusKEMExtractor(privKey.getKeyParams());

            byte[] encapsulation = extSpec.getEncapsulation();
            byte[] secret = kemExt.extractSecret(encapsulation);

            byte[] keyBytes = KdfUtil.makeKeyBytes(extSpec, secret);

            SecretKey rv = new SecretKeyWithEncapsulation(new SecretKeySpec(keyBytes, extSpec.getKeyAlgorithmName()), encapsulation);

            Arrays.clear(keyBytes);

            return rv;
        }
    }

    public static class NTRUPlus768
        extends NTRUPlusKeyGeneratorSpi
    {
        public NTRUPlus768()
        {
            super(NTRUPlusParameters.ntruplus_kem_768);
        }
    }

    public static class NTRUPlus864
        extends NTRUPlusKeyGeneratorSpi
    {
        public NTRUPlus864()
        {
            super(NTRUPlusParameters.ntruplus_kem_864);
        }
    }

    public static class NTRUPlus1152
        extends NTRUPlusKeyGeneratorSpi
    {
        public NTRUPlus1152()
        {
            super(NTRUPlusParameters.ntruplus_kem_1152);
        }
    }
}
