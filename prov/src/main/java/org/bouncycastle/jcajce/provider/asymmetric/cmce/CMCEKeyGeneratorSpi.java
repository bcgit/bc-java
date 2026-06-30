package org.bouncycastle.jcajce.provider.asymmetric.cmce;

import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.kems.CMCEKEMExtractor;
import org.bouncycastle.crypto.kems.CMCEKEMGenerator;
import org.bouncycastle.crypto.params.CMCEParameters;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.provider.asymmetric.util.KdfUtil;
import org.bouncycastle.jcajce.spec.CMCEParameterSpec;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.util.Arrays;

public class CMCEKeyGeneratorSpi
    extends KeyGeneratorSpi
{
    private final CMCEParameters cmceParameters;

    private KEMGenerateSpec genSpec;
    private SecureRandom random;
    private KEMExtractSpec extSpec;

    public CMCEKeyGeneratorSpi()
    {
        this(null);
    }

    protected CMCEKeyGeneratorSpi(CMCEParameters cmceParameters)
    {
        this.cmceParameters = cmceParameters;
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
            if (cmceParameters != null)
            {
                String canonicalAlgName = CMCEParameterSpec.fromName(cmceParameters.getName()).getName();
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
            if (cmceParameters != null)
            {
                String canonicalAlgName = CMCEParameterSpec.fromName(cmceParameters.getName()).getName();
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
            BCCMCEPublicKey pubKey = (BCCMCEPublicKey)genSpec.getPublicKey();
            CMCEKEMGenerator kemGen = new CMCEKEMGenerator(random);

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
            BCCMCEPrivateKey privKey = (BCCMCEPrivateKey)extSpec.getPrivateKey();
            CMCEKEMExtractor kemExt = new CMCEKEMExtractor(privKey.getKeyParams());

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

    public static class Mceliece460896
        extends CMCEKeyGeneratorSpi
    {
        public Mceliece460896()
        {
            super(CMCEParameters.mceliece460896);
        }
    }

    public static class Mceliece460896F
        extends CMCEKeyGeneratorSpi
    {
        public Mceliece460896F()
        {
            super(CMCEParameters.mceliece460896f);
        }
    }

    public static class Mceliece460896Pc
        extends CMCEKeyGeneratorSpi
    {
        public Mceliece460896Pc()
        {
            super(CMCEParameters.mceliece460896pc);
        }
    }

    public static class Mceliece460896Pcf
        extends CMCEKeyGeneratorSpi
    {
        public Mceliece460896Pcf()
        {
            super(CMCEParameters.mceliece460896pcf);
        }
    }

    public static class Mceliece6688128
        extends CMCEKeyGeneratorSpi
    {
        public Mceliece6688128()
        {
            super(CMCEParameters.mceliece6688128);
        }
    }

    public static class Mceliece6688128F
        extends CMCEKeyGeneratorSpi
    {
        public Mceliece6688128F()
        {
            super(CMCEParameters.mceliece6688128f);
        }
    }

    public static class Mceliece6688128Pc
        extends CMCEKeyGeneratorSpi
    {
        public Mceliece6688128Pc()
        {
            super(CMCEParameters.mceliece6688128pc);
        }
    }

    public static class Mceliece6688128Pcf
        extends CMCEKeyGeneratorSpi
    {
        public Mceliece6688128Pcf()
        {
            super(CMCEParameters.mceliece6688128pcf);
        }
    }

    public static class Mceliece6960119
        extends CMCEKeyGeneratorSpi
    {
        public Mceliece6960119()
        {
            super(CMCEParameters.mceliece6960119);
        }
    }

    public static class Mceliece6960119F
        extends CMCEKeyGeneratorSpi
    {
        public Mceliece6960119F()
        {
            super(CMCEParameters.mceliece6960119f);
        }
    }

    public static class Mceliece6960119Pc
        extends CMCEKeyGeneratorSpi
    {
        public Mceliece6960119Pc()
        {
            super(CMCEParameters.mceliece6960119pc);
        }
    }

    public static class Mceliece6960119Pcf
        extends CMCEKeyGeneratorSpi
    {
        public Mceliece6960119Pcf()
        {
            super(CMCEParameters.mceliece6960119pcf);
        }
    }

    public static class Mceliece8192128
        extends CMCEKeyGeneratorSpi
    {
        public Mceliece8192128()
        {
            super(CMCEParameters.mceliece8192128);
        }
    }

    public static class Mceliece8192128F
        extends CMCEKeyGeneratorSpi
    {
        public Mceliece8192128F()
        {
            super(CMCEParameters.mceliece8192128f);
        }
    }

    public static class Mceliece8192128Pc
        extends CMCEKeyGeneratorSpi
    {
        public Mceliece8192128Pc()
        {
            super(CMCEParameters.mceliece8192128pc);
        }
    }

    public static class Mceliece8192128Pcf
        extends CMCEKeyGeneratorSpi
    {
        public Mceliece8192128Pcf()
        {
            super(CMCEParameters.mceliece8192128pcf);
        }
    }
}
