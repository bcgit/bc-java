package org.bouncycastle.jcajce.provider.symmetric;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DefaultBufferedBlockCipher;
import org.bouncycastle.crypto.engines.LEAEngine;
import org.bouncycastle.crypto.generators.Poly1305KeyGenerator;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.macs.GMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.OFBBlockCipher;
import org.bouncycastle.internal.asn1.cms.CCMParameters;
import org.bouncycastle.internal.asn1.cms.GCMParameters;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseAlgorithmParameterGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseAlgorithmParameters;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseSecretKeyFactory;
import org.bouncycastle.jcajce.provider.symmetric.util.BlockCipherProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.GcmSpecUtil;
import org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;
import org.bouncycastle.jcajce.spec.AEADParameterSpec;

/**
 * JCA/JCE provider plumbing for the LEA (Lightweight Encryption Algorithm) block cipher.
 * Modelled on {@link AES}: 128-bit block cipher with 128/192/256-bit keys, registered for
 * ECB, CBC, CFB, OFB, GCM and CCM via the standard BC mode wrappers, plus CMAC, GMAC,
 * Poly1305 and a SecretKeyFactory.
 */
public final class LEA
{
    private static final Map<String, String> generalLeaAttributes = new HashMap<String, String>();

    static
    {
        generalLeaAttributes.put("SupportedKeyClasses", "javax.crypto.SecretKey");
        generalLeaAttributes.put("SupportedKeyFormats", "RAW");
    }

    private LEA()
    {
    }

    public static class ECB
        extends BaseBlockCipher
    {
        public ECB()
        {
            super(new BlockCipherProvider()
            {
                public BlockCipher get()
                {
                    return new LEAEngine();
                }
            });
        }
    }

    public static class ECB128
        extends BaseBlockCipher
    {
        public ECB128()
        {
            super(128, new BlockCipherProvider()
            {
                public BlockCipher get()
                {
                    return new LEAEngine();
                }
            });
        }
    }

    public static class ECB192
        extends BaseBlockCipher
    {
        public ECB192()
        {
            super(192, new BlockCipherProvider()
            {
                public BlockCipher get()
                {
                    return new LEAEngine();
                }
            });
        }
    }

    public static class ECB256
        extends BaseBlockCipher
    {
        public ECB256()
        {
            super(256, new BlockCipherProvider()
            {
                public BlockCipher get()
                {
                    return new LEAEngine();
                }
            });
        }
    }

    public static class CBC
        extends BaseBlockCipher
    {
        public CBC()
        {
            super(CBCBlockCipher.newInstance(new LEAEngine()), 128);
        }
    }

    public static class CBC128
        extends BaseBlockCipher
    {
        public CBC128()
        {
            super(128, CBCBlockCipher.newInstance(new LEAEngine()), 128);
        }
    }

    public static class CBC192
        extends BaseBlockCipher
    {
        public CBC192()
        {
            super(192, CBCBlockCipher.newInstance(new LEAEngine()), 128);
        }
    }

    public static class CBC256
        extends BaseBlockCipher
    {
        public CBC256()
        {
            super(256, CBCBlockCipher.newInstance(new LEAEngine()), 128);
        }
    }

    public static class CFB
        extends BaseBlockCipher
    {
        public CFB()
        {
            super(new DefaultBufferedBlockCipher(CFBBlockCipher.newInstance(new LEAEngine(), 128)), 128);
        }
    }

    public static class OFB
        extends BaseBlockCipher
    {
        public OFB()
        {
            super(new DefaultBufferedBlockCipher(new OFBBlockCipher(new LEAEngine(), 128)), 128);
        }
    }

    public static class GCM
        extends BaseBlockCipher
    {
        public GCM()
        {
            super(GCMBlockCipher.newInstance(new LEAEngine()));
        }
    }

    public static class CCM
        extends BaseBlockCipher
    {
        public CCM()
        {
            super(CCMBlockCipher.newInstance(new LEAEngine()), false, 12);
        }
    }

    public static class KeyGen
        extends BaseKeyGenerator
    {
        public KeyGen()
        {
            this(128);
        }

        public KeyGen(int keySize)
        {
            super("LEA", keySize, new CipherKeyGenerator());
        }
    }

    public static class KeyGen128
        extends KeyGen
    {
        public KeyGen128()
        {
            super(128);
        }
    }

    public static class KeyGen192
        extends KeyGen
    {
        public KeyGen192()
        {
            super(192);
        }
    }

    public static class KeyGen256
        extends KeyGen
    {
        public KeyGen256()
        {
            super(256);
        }
    }

    public static class KeyFactory
        extends BaseSecretKeyFactory
    {
        public KeyFactory()
        {
            super("LEA", null);
        }
    }

    public static class CMAC
        extends BaseMac
    {
        public CMAC()
        {
            super(new CMac(new LEAEngine()));
        }
    }

    public static class GMAC
        extends BaseMac
    {
        public GMAC()
        {
            super(new GMac(GCMBlockCipher.newInstance(new LEAEngine())));
        }
    }

    public static class Poly1305
        extends BaseMac
    {
        public Poly1305()
        {
            super(new org.bouncycastle.crypto.macs.Poly1305(new LEAEngine()));
        }
    }

    public static class Poly1305KeyGen
        extends BaseKeyGenerator
    {
        public Poly1305KeyGen()
        {
            super("Poly1305-LEA", 256, new Poly1305KeyGenerator());
        }
    }

    public static class AlgParamGen
        extends BaseAlgorithmParameterGenerator
    {
        protected void engineInit(
            AlgorithmParameterSpec genParamSpec,
            SecureRandom random)
            throws InvalidAlgorithmParameterException
        {
            throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for LEA parameter generation.");
        }

        protected AlgorithmParameters engineGenerateParameters()
        {
            byte[] iv = new byte[16];

            if (random == null)
            {
                random = CryptoServicesRegistrar.getSecureRandom();
            }

            random.nextBytes(iv);

            AlgorithmParameters params;
            try
            {
                params = createParametersInstance("LEA");
                params.init(new IvParameterSpec(iv));
            }
            catch (Exception e)
            {
                throw new RuntimeException(e.getMessage());
            }

            return params;
        }
    }

    public static class AlgParamGenCCM
        extends BaseAlgorithmParameterGenerator
    {
        protected void engineInit(
            AlgorithmParameterSpec genParamSpec,
            SecureRandom random)
            throws InvalidAlgorithmParameterException
        {
            throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for LEA parameter generation.");
        }

        protected AlgorithmParameters engineGenerateParameters()
        {
            random = CryptoServicesRegistrar.getSecureRandom(random);

            byte[] nonce = new byte[12];
            random.nextBytes(nonce);

            AlgorithmParameters params;
            try
            {
                params = createParametersInstance("CCM");
                params.init(new CCMParameters(nonce, 12).getEncoded());
            }
            catch (Exception e)
            {
                throw new RuntimeException(e.getMessage());
            }

            return params;
        }
    }

    public static class AlgParamGenGCM
        extends BaseAlgorithmParameterGenerator
    {
        protected void engineInit(
            AlgorithmParameterSpec genParamSpec,
            SecureRandom random)
            throws InvalidAlgorithmParameterException
        {
            throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for LEA parameter generation.");
        }

        protected AlgorithmParameters engineGenerateParameters()
        {
            random = CryptoServicesRegistrar.getSecureRandom(random);

            byte[] nonce = new byte[12];
            random.nextBytes(nonce);

            AlgorithmParameters params;
            try
            {
                params = createParametersInstance("GCM");
                params.init(new GCMParameters(nonce, 16).getEncoded());
            }
            catch (Exception e)
            {
                throw new RuntimeException(e.getMessage());
            }

            return params;
        }
    }

    public static class AlgParams
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "LEA IV";
        }
    }

    public static class AlgParamsGCM
        extends BaseAlgorithmParameters
    {
        private GCMParameters gcmParams;

        protected void engineInit(AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException
        {
            if (GcmSpecUtil.isGcmSpec(paramSpec))
            {
                gcmParams = GCMParameters.getInstance(GcmSpecUtil.extractGcmParameters(paramSpec));
            }
            else if (paramSpec instanceof AEADParameterSpec)
            {
                gcmParams = new GCMParameters(((AEADParameterSpec)paramSpec).getNonce(),
                    ((AEADParameterSpec)paramSpec).getMacSizeInBits() / 8);
            }
            else
            {
                throw new InvalidParameterSpecException("AlgorithmParameterSpec class not recognized: " + paramSpec.getClass().getName());
            }
        }

        protected void engineInit(byte[] params)
            throws IOException
        {
            gcmParams = GCMParameters.getInstance(params);
        }

        protected void engineInit(byte[] params, String format)
            throws IOException
        {
            if (!isASN1FormatString(format))
            {
                throw new IOException("unknown format specified");
            }

            gcmParams = GCMParameters.getInstance(params);
        }

        protected byte[] engineGetEncoded()
            throws IOException
        {
            return gcmParams.getEncoded();
        }

        protected byte[] engineGetEncoded(String format)
            throws IOException
        {
            if (!isASN1FormatString(format))
            {
                throw new IOException("unknown format specified");
            }

            return gcmParams.getEncoded();
        }

        protected String engineToString()
        {
            return "GCM";
        }

        protected AlgorithmParameterSpec localEngineGetParameterSpec(Class paramSpec)
            throws InvalidParameterSpecException
        {
            if (paramSpec == AlgorithmParameterSpec.class || GcmSpecUtil.isGcmSpec(paramSpec))
            {
                if (GcmSpecUtil.gcmSpecExtractable())
                {
                    return GcmSpecUtil.extractGcmSpec(gcmParams.toASN1Primitive());
                }
                return new AEADParameterSpec(gcmParams.getNonce(), gcmParams.getIcvLen() * 8);
            }
            if (paramSpec == AEADParameterSpec.class)
            {
                return new AEADParameterSpec(gcmParams.getNonce(), gcmParams.getIcvLen() * 8);
            }
            if (paramSpec == IvParameterSpec.class)
            {
                return new IvParameterSpec(gcmParams.getNonce());
            }

            throw new InvalidParameterSpecException("AlgorithmParameterSpec not recognized: " + paramSpec.getName());
        }
    }

    public static class AlgParamsCCM
        extends BaseAlgorithmParameters
    {
        private CCMParameters ccmParams;

        protected void engineInit(AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException
        {
            if (GcmSpecUtil.isGcmSpec(paramSpec))
            {
                ccmParams = CCMParameters.getInstance(GcmSpecUtil.extractGcmParameters(paramSpec));
            }
            else if (paramSpec instanceof AEADParameterSpec)
            {
                ccmParams = new CCMParameters(((AEADParameterSpec)paramSpec).getNonce(),
                    ((AEADParameterSpec)paramSpec).getMacSizeInBits() / 8);
            }
            else
            {
                throw new InvalidParameterSpecException("AlgorithmParameterSpec class not recognized: " + paramSpec.getClass().getName());
            }
        }

        protected void engineInit(byte[] params)
            throws IOException
        {
            ccmParams = CCMParameters.getInstance(params);
        }

        protected void engineInit(byte[] params, String format)
            throws IOException
        {
            if (!isASN1FormatString(format))
            {
                throw new IOException("unknown format specified");
            }

            ccmParams = CCMParameters.getInstance(params);
        }

        protected byte[] engineGetEncoded()
            throws IOException
        {
            return ccmParams.getEncoded();
        }

        protected byte[] engineGetEncoded(String format)
            throws IOException
        {
            if (!isASN1FormatString(format))
            {
                throw new IOException("unknown format specified");
            }

            return ccmParams.getEncoded();
        }

        protected String engineToString()
        {
            return "CCM";
        }

        protected AlgorithmParameterSpec localEngineGetParameterSpec(Class paramSpec)
            throws InvalidParameterSpecException
        {
            if (paramSpec == AlgorithmParameterSpec.class || GcmSpecUtil.isGcmSpec(paramSpec))
            {
                if (GcmSpecUtil.gcmSpecExtractable())
                {
                    return GcmSpecUtil.extractGcmSpec(ccmParams.toASN1Primitive());
                }
                return new AEADParameterSpec(ccmParams.getNonce(), ccmParams.getIcvLen() * 8);
            }
            if (paramSpec == AEADParameterSpec.class)
            {
                return new AEADParameterSpec(ccmParams.getNonce(), ccmParams.getIcvLen() * 8);
            }
            if (paramSpec == IvParameterSpec.class)
            {
                return new IvParameterSpec(ccmParams.getNonce());
            }

            throw new InvalidParameterSpecException("AlgorithmParameterSpec not recognized: " + paramSpec.getName());
        }
    }

    public static class Mappings
        extends SymmetricAlgorithmProvider
    {
        private static final String PREFIX = LEA.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("AlgorithmParameters.LEA", PREFIX + "$AlgParams");
            provider.addAlgorithm("AlgorithmParameters.LEA-GCM", PREFIX + "$AlgParamsGCM");
            provider.addAlgorithm("AlgorithmParameters.LEA-CCM", PREFIX + "$AlgParamsCCM");

            provider.addAlgorithm("AlgorithmParameterGenerator.LEA", PREFIX + "$AlgParamGen");
            provider.addAlgorithm("AlgorithmParameterGenerator.LEA-GCM", PREFIX + "$AlgParamGenGCM");
            provider.addAlgorithm("AlgorithmParameterGenerator.LEA-CCM", PREFIX + "$AlgParamGenCCM");

            provider.addAttributes("Cipher.LEA", generalLeaAttributes);
            provider.addAlgorithm("Cipher.LEA", PREFIX + "$ECB");

            provider.addAttributes("Cipher.LEA-GCM", generalLeaAttributes);
            provider.addAlgorithm("Cipher.LEA-GCM", PREFIX + "$GCM");

            provider.addAttributes("Cipher.LEA-CCM", generalLeaAttributes);
            provider.addAlgorithm("Cipher.LEA-CCM", PREFIX + "$CCM");

            provider.addAlgorithm("KeyGenerator.LEA", PREFIX + "$KeyGen");
            provider.addAlgorithm("KeyGenerator.LEA-GCM", PREFIX + "$KeyGen");
            provider.addAlgorithm("KeyGenerator.LEA-CCM", PREFIX + "$KeyGen");

            provider.addAlgorithm("SecretKeyFactory.LEA", PREFIX + "$KeyFactory");

            addCMacAlgorithm(provider, "LEA", PREFIX + "$CMAC", PREFIX + "$KeyGen");
            addGMacAlgorithm(provider, "LEA", PREFIX + "$GMAC", PREFIX + "$KeyGen128");
            addPoly1305Algorithm(provider, "LEA", PREFIX + "$Poly1305", PREFIX + "$Poly1305KeyGen");
        }
    }
}
