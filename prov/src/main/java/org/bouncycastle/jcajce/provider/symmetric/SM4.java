package org.bouncycastle.jcajce.provider.symmetric;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.engines.RFC3394WrapEngine;
import org.bouncycastle.crypto.engines.RFC5649WrapEngine;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.generators.Poly1305KeyGenerator;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.macs.GMac;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.internal.asn1.cms.CCMParameters;
import org.bouncycastle.internal.asn1.cms.GCMParameters;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseAlgorithmParameterGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseAlgorithmParameters;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseWrapCipher;
import org.bouncycastle.jcajce.provider.symmetric.util.BlockCipherProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.GcmSpecUtil;
import org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;
import org.bouncycastle.jcajce.spec.AEADParameterSpec;

public final class SM4
{
    private SM4()
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
                    return new SM4Engine();
                }
            });
        }
    }

    static public class CCM
        extends BaseBlockCipher
    {
        public CCM()
        {
            super(CCMBlockCipher.newInstance(new SM4Engine()), false, 12);
        }
    }

    static public class GCM
        extends BaseBlockCipher
    {
        public GCM()
        {
            super(GCMBlockCipher.newInstance(new SM4Engine()));
        }
    }

    public static class KeyGen
        extends BaseKeyGenerator
    {
        public KeyGen()
        {
            super("SM4", 128, new CipherKeyGenerator());
        }
    }

    public static class CMAC
        extends BaseMac
    {
        public CMAC()
        {
            super(new CMac(new SM4Engine()));
        }
    }

    public static class GMAC
        extends BaseMac
    {
        public GMAC()
        {
            super(new GMac(GCMBlockCipher.newInstance(new SM4Engine())));
        }
    }

    public static class Poly1305
        extends BaseMac
    {
        public Poly1305()
        {
            super(new org.bouncycastle.crypto.macs.Poly1305(new SM4Engine()));
        }
    }

    public static class Poly1305KeyGen
        extends BaseKeyGenerator
    {
        public Poly1305KeyGen()
        {
            super("Poly1305-SM4", 256, new Poly1305KeyGenerator());
        }
    }

    public static class Wrap
        extends BaseWrapCipher
    {
        public Wrap()
        {
            super(new SM4WrapEngine());
        }
    }

    public static class WrapPad
        extends BaseWrapCipher
    {
        public WrapPad()
        {
            super(new SM4WrapPadEngine());
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
            throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for SM4 parameter generation.");
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
                params = createParametersInstance("SM4");
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
            throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for SM4 parameter generation.");
        }

        protected AlgorithmParameters engineGenerateParameters()
        {
            random = CryptoServicesRegistrar.getSecureRandom(random);

            byte[] nonce = new byte[12];
            random.nextBytes(nonce);

            AlgorithmParameters params;
            try
            {
                params = createParametersInstance("SM4-CCM");
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
            throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for SM4 parameter generation.");
        }

        protected AlgorithmParameters engineGenerateParameters()
        {
            random = CryptoServicesRegistrar.getSecureRandom(random);

            byte[] nonce = new byte[12];
            random.nextBytes(nonce);

            AlgorithmParameters params;
            try
            {
                params = createParametersInstance("SM4-GCM");
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
            return "SM4 IV";
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
                gcmParams = new GCMParameters(((AEADParameterSpec)paramSpec).getNonce(), ((AEADParameterSpec)paramSpec).getMacSizeInBits() / 8);
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
                ccmParams = CCMParameters.getInstance(GcmSpecUtil.extractCcmParameters(paramSpec));
            }
            else if (paramSpec instanceof AEADParameterSpec)
            {
                ccmParams = new CCMParameters(((AEADParameterSpec)paramSpec).getNonce(), ((AEADParameterSpec)paramSpec).getMacSizeInBits() / 8);
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
        private static final String PREFIX = SM4.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("AlgorithmParameters.SM4", PREFIX + "$AlgParams");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + GMObjectIdentifiers.sms4_cbc, "SM4");

            provider.addAlgorithm("AlgorithmParameterGenerator.SM4", PREFIX + "$AlgParamGen");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator." + GMObjectIdentifiers.sms4_cbc, "SM4");

            provider.addAlgorithm("Cipher.SM4", PREFIX + "$ECB");

            provider.addAlgorithm("Cipher.SM4-GCM", PREFIX + "$GCM");
            provider.addAlgorithm("Alg.Alias.Cipher", GMObjectIdentifiers.sms4_gcm, "SM4-GCM");
            provider.addAlgorithm("AlgorithmParameters.SM4-GCM", PREFIX + "$AlgParamsGCM");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + GMObjectIdentifiers.sms4_gcm, "SM4-GCM");
            provider.addAlgorithm("AlgorithmParameterGenerator.SM4-GCM", PREFIX + "$AlgParamGenGCM");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator." + GMObjectIdentifiers.sms4_gcm, "SM4-GCM");

            provider.addAlgorithm("Cipher.SM4-CCM", PREFIX + "$CCM");
            provider.addAlgorithm("Alg.Alias.Cipher", GMObjectIdentifiers.sms4_ccm, "SM4-CCM");
            provider.addAlgorithm("AlgorithmParameters.SM4-CCM", PREFIX + "$AlgParamsCCM");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + GMObjectIdentifiers.sms4_ccm, "SM4-CCM");
            provider.addAlgorithm("AlgorithmParameterGenerator.SM4-CCM", PREFIX + "$AlgParamGenCCM");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator." + GMObjectIdentifiers.sms4_ccm, "SM4-CCM");

            provider.addAlgorithm("KeyGenerator.SM4", PREFIX + "$KeyGen");
            provider.addAlgorithm("KeyGenerator", GMObjectIdentifiers.sms4_gcm, PREFIX + "$KeyGen");
            provider.addAlgorithm("KeyGenerator", GMObjectIdentifiers.sms4_ccm, PREFIX + "$KeyGen");

            addCMacAlgorithm(provider, "SM4", PREFIX + "$CMAC", PREFIX + "$KeyGen");
            addGMacAlgorithm(provider, "SM4", PREFIX + "$GMAC", PREFIX + "$KeyGen");
            addPoly1305Algorithm(provider, "SM4", PREFIX + "$Poly1305", PREFIX + "$Poly1305KeyGen");

            provider.addAlgorithm("Cipher.SM4WRAP", PREFIX + "$Wrap");
            provider.addAlgorithm("Cipher.SM4WRAPPAD", PREFIX + "$WrapPad");
            provider.addAlgorithm("Cipher", GMObjectIdentifiers.sms4_wrap, PREFIX + "$Wrap");
            provider.addAlgorithm("Cipher", GMObjectIdentifiers.sms4_wrap_pad, PREFIX + "$WrapPad");
        }
    }

    private static class SM4WrapEngine
        extends RFC3394WrapEngine
    {
        public SM4WrapEngine()
        {
            super(new SM4Engine());
        }
    }

    private static class SM4WrapPadEngine
        extends RFC5649WrapEngine
    {
        public SM4WrapPadEngine()
        {
            super(new SM4Engine());
        }
    }
}
