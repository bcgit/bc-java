package org.bouncycastle.jcajce.provider.symmetric;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.asn1.ua.UAObjectIdentifiers;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.engines.DSTU7624Engine;
import org.bouncycastle.crypto.engines.DSTU7624WrapEngine;
import org.bouncycastle.crypto.macs.KGMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.KCCMBlockCipher;
import org.bouncycastle.crypto.modes.KCTRBlockCipher;
import org.bouncycastle.crypto.modes.KGCMBlockCipher;
import org.bouncycastle.crypto.modes.OFBBlockCipher;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseAlgorithmParameterGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseWrapCipher;
import org.bouncycastle.jcajce.provider.symmetric.util.BlockCipherProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;

public class DSTU7624
{
    private DSTU7624()
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
                    return new DSTU7624Engine(128);
                }
            });
        }
    }

    // these next three allow some variation on the keysize used in each case.
    public static class ECB_128
       extends BaseBlockCipher
    {
        public ECB_128()
        {
            super(new DSTU7624Engine(128));
        }
    }

    public static class ECB_256
       extends BaseBlockCipher
    {
        public ECB_256()
        {
            super(new DSTU7624Engine(256));
        }
    }

    public static class ECB_512
       extends BaseBlockCipher
    {
        public ECB_512()
        {
            super(new DSTU7624Engine(512));
        }
    }

    // what follows is fixed with a key size the same as the block size.
    public static class ECB128
       extends BaseBlockCipher
    {
        public ECB128()
        {    // TODO: key size is also meant to be fixed
            super(new DSTU7624Engine(128));
        }
    }

    public static class ECB256
       extends BaseBlockCipher
    {
        public ECB256()
        {
            super(new DSTU7624Engine(256));
        }
    }

    public static class ECB512
       extends BaseBlockCipher
    {
        public ECB512()
        {
            super(new DSTU7624Engine(512));
        }
    }

    public static class CBC128
       extends BaseBlockCipher
    {
        public CBC128()
        {    // TODO: key size is also meant to be fixed
            super(new CBCBlockCipher(new DSTU7624Engine(128)), 128);
        }
    }

    public static class CBC256
       extends BaseBlockCipher
    {
        public CBC256()
        {
            super(new CBCBlockCipher(new DSTU7624Engine(256)), 256);
        }
    }

    public static class CBC512
       extends BaseBlockCipher
    {
        public CBC512()
        {
            super(new CBCBlockCipher(new DSTU7624Engine(512)), 512);
        }
    }

    public static class OFB128
       extends BaseBlockCipher
    {
        public OFB128()
        {    // TODO: key size is also meant to be fixed
            super(new BufferedBlockCipher(new OFBBlockCipher(new DSTU7624Engine(128), 128)), 128);
        }
    }

    public static class OFB256
       extends BaseBlockCipher
    {
        public OFB256()
        {
            super(new BufferedBlockCipher(new OFBBlockCipher(new DSTU7624Engine(256), 256)), 256);
        }
    }

    public static class OFB512
       extends BaseBlockCipher
    {
        public OFB512()
        {
            super(new BufferedBlockCipher(new OFBBlockCipher(new DSTU7624Engine(512), 512)), 512);
        }
    }

    public static class CFB128
       extends BaseBlockCipher
    {
        public CFB128()
        {    // TODO: key size is also meant to be fixed
            super(new BufferedBlockCipher(new CFBBlockCipher(new DSTU7624Engine(128), 128)), 128);
        }
    }

    public static class CFB256
       extends BaseBlockCipher
    {
        public CFB256()
        {
            super(new BufferedBlockCipher(new CFBBlockCipher(new DSTU7624Engine(256), 256)), 256);
        }
    }

    public static class CFB512
       extends BaseBlockCipher
    {
        public CFB512()
        {
            super(new BufferedBlockCipher(new CFBBlockCipher(new DSTU7624Engine(512), 512)), 512);
        }
    }

    public static class CTR128
       extends BaseBlockCipher
    {
        public CTR128()
        {    // TODO: key size is also meant to be fixed
            super(new BufferedBlockCipher(new KCTRBlockCipher(new DSTU7624Engine(128))), 128);
        }
    }

    public static class CTR256
       extends BaseBlockCipher
    {
        public CTR256()
        {
            super(new BufferedBlockCipher(new KCTRBlockCipher(new DSTU7624Engine(256))), 256);
        }
    }

    public static class CTR512
       extends BaseBlockCipher
    {
        public CTR512()
        {
            super(new BufferedBlockCipher(new KCTRBlockCipher(new DSTU7624Engine(512))), 512);
        }
    }

    public static class CCM128
       extends BaseBlockCipher
    {
        public CCM128()
        {    // TODO: key size is also meant to be fixed
            super(new KCCMBlockCipher(new DSTU7624Engine(128)));
        }
    }

    public static class CCM256
       extends BaseBlockCipher
    {
        public CCM256()
        {
            super(new KCCMBlockCipher(new DSTU7624Engine(256)));
        }
    }

    public static class CCM512
       extends BaseBlockCipher
    {
        public CCM512()
        {
            super(new KCCMBlockCipher(new DSTU7624Engine(512)));
        }
    }

    public static class GCM128
       extends BaseBlockCipher
    {
        public GCM128()
        {    // TODO: key size is also meant to be fixed
            super(new KGCMBlockCipher(new DSTU7624Engine(128)));
        }
    }

    public static class GCM256
       extends BaseBlockCipher
    {
        public GCM256()
        {
            super(new KGCMBlockCipher(new DSTU7624Engine(256)));
        }
    }

    public static class GCM512
       extends BaseBlockCipher
    {
        public GCM512()
        {
            super(new KGCMBlockCipher(new DSTU7624Engine(512)));
        }
    }

    public static class Wrap
        extends BaseWrapCipher
    {
        public Wrap()
        {
            super(new DSTU7624WrapEngine(128));
        }
    }

    public static class Wrap128
        extends BaseWrapCipher
    {
        public Wrap128()
        {
            super(new DSTU7624WrapEngine(128));
        }
    }

    public static class Wrap256
        extends BaseWrapCipher
    {
        public Wrap256()
        {
            super(new DSTU7624WrapEngine(256));
        }
    }

    public static class Wrap512
        extends BaseWrapCipher
    {
        public Wrap512()
        {
            super(new DSTU7624WrapEngine(512));
        }
    }

    public static class GMAC
        extends BaseMac
    {
        public GMAC()
        {
            super(new KGMac(new KGCMBlockCipher(new DSTU7624Engine(128)), 128));
        }
    }
       // TODO: enforce key size restriction
    public static class GMAC128
        extends BaseMac
    {
        public GMAC128()
        {
            super(new KGMac(new KGCMBlockCipher(new DSTU7624Engine(128)), 128));
        }
    }

    public static class GMAC256
        extends BaseMac
    {
        public GMAC256()
        {
            super(new KGMac(new KGCMBlockCipher(new DSTU7624Engine(256)), 256));
        }
    }

    public static class GMAC512
        extends BaseMac
    {
        public GMAC512()
        {
            super(new KGMac(new KGCMBlockCipher(new DSTU7624Engine(512)), 512));
        }
    }

    public static class KeyGen
        extends BaseKeyGenerator
    {
        public KeyGen()
        {
            this(256);
        }

        public KeyGen(int keySize)
        {
            super("DSTU7624", keySize, new CipherKeyGenerator());
        }
    }

    public static class KeyGen128
        extends DSTU7624.KeyGen
    {
        public KeyGen128()
        {
            super(128);
        }
    }

    public static class KeyGen256
        extends DSTU7624.KeyGen
    {
        public KeyGen256()
        {
            super(256);
        }
    }

    public static class KeyGen512
        extends DSTU7624.KeyGen
    {
        public KeyGen512()
        {
            super(512);
        }
    }

    public static class AlgParamGen
        extends BaseAlgorithmParameterGenerator
    {
        private final int ivLength;

        public AlgParamGen(int blockSize)
        {
            this.ivLength = blockSize / 8;
        }

        protected void engineInit(
            AlgorithmParameterSpec genParamSpec,
            SecureRandom random)
            throws InvalidAlgorithmParameterException
        {
            throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for DSTU7624 parameter generation.");
        }

        protected AlgorithmParameters engineGenerateParameters()
        {
            byte[] iv = new byte[ivLength];

            if (random == null)
            {
                random = CryptoServicesRegistrar.getSecureRandom();
            }

            random.nextBytes(iv);

            AlgorithmParameters params;

            try
            {
                params = createParametersInstance("DSTU7624");
                params.init(new IvParameterSpec(iv));
            }
            catch (Exception e)
            {
                throw new RuntimeException(e.getMessage());
            }

            return params;
        }
    }

    public static class AlgParamGen128
        extends AlgParamGen
    {
        public AlgParamGen128()
        {
            super(128);
        }
    }

    public static class AlgParamGen256
        extends AlgParamGen
    {
        public AlgParamGen256()
        {
            super(256);
        }
    }

    public static class AlgParamGen512
        extends AlgParamGen
    {
        public AlgParamGen512()
        {
            super(512);
        }
    }

    public static class AlgParams
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "DSTU7624 IV";
        }
    }

    public static class Mappings
        extends SymmetricAlgorithmProvider
    {
        private static final String PREFIX = DSTU7624.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {

            provider.addAlgorithm("AlgorithmParameters.DSTU7624", PREFIX + "$AlgParams");
            provider.addAlgorithm("AlgorithmParameters", UAObjectIdentifiers.dstu7624cbc_128, PREFIX + "$AlgParams");
            provider.addAlgorithm("AlgorithmParameters",  UAObjectIdentifiers.dstu7624cbc_256, PREFIX + "$AlgParams");
            provider.addAlgorithm("AlgorithmParameters",  UAObjectIdentifiers.dstu7624cbc_512, PREFIX + "$AlgParams");

            provider.addAlgorithm("AlgorithmParameterGenerator.DSTU7624", PREFIX + "$AlgParamGen128");
            provider.addAlgorithm("AlgorithmParameterGenerator", UAObjectIdentifiers.dstu7624cbc_128, PREFIX + "$AlgParamGen128");
            provider.addAlgorithm("AlgorithmParameterGenerator", UAObjectIdentifiers.dstu7624cbc_256, PREFIX + "$AlgParamGen256");
            provider.addAlgorithm("AlgorithmParameterGenerator", UAObjectIdentifiers.dstu7624cbc_512, PREFIX + "$AlgParamGen512");

            provider.addAlgorithm("Cipher.DSTU7624", PREFIX + "$ECB_128");
            provider.addAlgorithm("Cipher.DSTU7624-128", PREFIX + "$ECB_128");
            provider.addAlgorithm("Cipher.DSTU7624-256", PREFIX + "$ECB_256");
            provider.addAlgorithm("Cipher.DSTU7624-512", PREFIX + "$ECB_512");

            provider.addAlgorithm("Cipher", UAObjectIdentifiers.dstu7624ecb_128, PREFIX + "$ECB128");
            provider.addAlgorithm("Cipher", UAObjectIdentifiers.dstu7624ecb_256, PREFIX + "$ECB256");
            provider.addAlgorithm("Cipher", UAObjectIdentifiers.dstu7624ecb_512, PREFIX + "$ECB512");

            provider.addAlgorithm("Cipher", UAObjectIdentifiers.dstu7624cbc_128, PREFIX + "$CBC128");
            provider.addAlgorithm("Cipher", UAObjectIdentifiers.dstu7624cbc_256, PREFIX + "$CBC256");
            provider.addAlgorithm("Cipher", UAObjectIdentifiers.dstu7624cbc_512, PREFIX + "$CBC512");

            provider.addAlgorithm("Cipher", UAObjectIdentifiers.dstu7624ofb_128, PREFIX + "$OFB128");
            provider.addAlgorithm("Cipher", UAObjectIdentifiers.dstu7624ofb_256, PREFIX + "$OFB256");
            provider.addAlgorithm("Cipher", UAObjectIdentifiers.dstu7624ofb_512, PREFIX + "$OFB512");

            provider.addAlgorithm("Cipher", UAObjectIdentifiers.dstu7624cfb_128, PREFIX + "$CFB128");
            provider.addAlgorithm("Cipher", UAObjectIdentifiers.dstu7624cfb_256, PREFIX + "$CFB256");
            provider.addAlgorithm("Cipher", UAObjectIdentifiers.dstu7624cfb_512, PREFIX + "$CFB512");

            provider.addAlgorithm("Cipher", UAObjectIdentifiers.dstu7624ctr_128, PREFIX + "$CTR128");
            provider.addAlgorithm("Cipher", UAObjectIdentifiers.dstu7624ctr_256, PREFIX + "$CTR256");
            provider.addAlgorithm("Cipher", UAObjectIdentifiers.dstu7624ctr_512, PREFIX + "$CTR512");

            provider.addAlgorithm("Cipher", UAObjectIdentifiers.dstu7624ccm_128, PREFIX + "$CCM128");
            provider.addAlgorithm("Cipher", UAObjectIdentifiers.dstu7624ccm_256, PREFIX + "$CCM256");
            provider.addAlgorithm("Cipher", UAObjectIdentifiers.dstu7624ccm_512, PREFIX + "$CCM512");

            provider.addAlgorithm("Cipher.DSTU7624KW", PREFIX + "$Wrap");
            provider.addAlgorithm("Alg.Alias.Cipher.DSTU7624WRAP", "DSTU7624KW");
            provider.addAlgorithm("Cipher.DSTU7624-128KW", PREFIX + "$Wrap128");
            provider.addAlgorithm("Alg.Alias.Cipher." + UAObjectIdentifiers.dstu7624kw_128.getId(), "DSTU7624-128KW");
            provider.addAlgorithm("Alg.Alias.Cipher.DSTU7624-128WRAP", "DSTU7624-128KW");
            provider.addAlgorithm("Cipher.DSTU7624-256KW", PREFIX + "$Wrap256");
            provider.addAlgorithm("Alg.Alias.Cipher." + UAObjectIdentifiers.dstu7624kw_256.getId(), "DSTU7624-256KW");
            provider.addAlgorithm("Alg.Alias.Cipher.DSTU7624-256WRAP", "DSTU7624-256KW");
            provider.addAlgorithm("Cipher.DSTU7624-512KW", PREFIX + "$Wrap512");
            provider.addAlgorithm("Alg.Alias.Cipher." + UAObjectIdentifiers.dstu7624kw_512.getId(), "DSTU7624-512KW");
            provider.addAlgorithm("Alg.Alias.Cipher.DSTU7624-512WRAP", "DSTU7624-512KW");

            provider.addAlgorithm("Mac.DSTU7624GMAC", PREFIX + "$GMAC");
            provider.addAlgorithm("Mac.DSTU7624-128GMAC", PREFIX + "$GMAC128");
            provider.addAlgorithm("Alg.Alias.Mac." + UAObjectIdentifiers.dstu7624gmac_128.getId(), "DSTU7624-128GMAC");
            provider.addAlgorithm("Mac.DSTU7624-256GMAC", PREFIX + "$GMAC256");
            provider.addAlgorithm("Alg.Alias.Mac." + UAObjectIdentifiers.dstu7624gmac_256.getId(), "DSTU7624-256GMAC");
            provider.addAlgorithm("Mac.DSTU7624-512GMAC", PREFIX + "$GMAC512");
            provider.addAlgorithm("Alg.Alias.Mac." + UAObjectIdentifiers.dstu7624gmac_512.getId(), "DSTU7624-512GMAC");
            
            provider.addAlgorithm("KeyGenerator.DSTU7624", PREFIX + "$KeyGen");
            provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers.dstu7624kw_128, PREFIX + "$KeyGen128");
            provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers.dstu7624kw_256, PREFIX + "$KeyGen256");
            provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers.dstu7624kw_512, PREFIX + "$KeyGen512");
            provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers.dstu7624ecb_128, PREFIX + "$KeyGen128");
            provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers.dstu7624ecb_256, PREFIX + "$KeyGen256");
            provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers.dstu7624ecb_512, PREFIX + "$KeyGen512");
            provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers.dstu7624cbc_128, PREFIX + "$KeyGen128");
            provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers.dstu7624cbc_256, PREFIX + "$KeyGen256");
            provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers.dstu7624cbc_512, PREFIX + "$KeyGen512");
            provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers.dstu7624ofb_128, PREFIX + "$KeyGen128");
            provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers.dstu7624ofb_256, PREFIX + "$KeyGen256");
            provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers.dstu7624ofb_512, PREFIX + "$KeyGen512");
            provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers.dstu7624cfb_128, PREFIX + "$KeyGen128");
            provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers.dstu7624cfb_256, PREFIX + "$KeyGen256");
            provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers.dstu7624cfb_512, PREFIX + "$KeyGen512");
            provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers.dstu7624ctr_128, PREFIX + "$KeyGen128");
            provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers.dstu7624ctr_256, PREFIX + "$KeyGen256");
            provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers.dstu7624ctr_512, PREFIX + "$KeyGen512");
            provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers.dstu7624ccm_128, PREFIX + "$KeyGen128");
            provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers.dstu7624ccm_256, PREFIX + "$KeyGen256");
            provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers.dstu7624ccm_512, PREFIX + "$KeyGen512");
            provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers.dstu7624gmac_128, PREFIX + "$KeyGen128");
            provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers.dstu7624gmac_256, PREFIX + "$KeyGen256");
            provider.addAlgorithm("KeyGenerator", UAObjectIdentifiers.dstu7624gmac_512, PREFIX + "$KeyGen512");
        }
    }
}
