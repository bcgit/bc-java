package org.bouncycastle.jcajce.provider.symmetric;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.crypto.generators.Poly1305KeyGenerator;
import org.bouncycastle.crypto.macs.GMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
import org.bouncycastle.jcajce.provider.symmetric.util.BlockCipherProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;
import org.bouncycastle.jcajce.provider.symmetric.util.PBESecretKeyFactory;

public final class Twofish
{
    private Twofish()
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
                    return new TwofishEngine();
                }
            });
        }
    }

    public static class KeyGen
        extends BaseKeyGenerator
    {
        public KeyGen()
        {
            super("Twofish", 256, new CipherKeyGenerator());
        }
    }

    public static class GMAC
        extends BaseMac
    {
        public GMAC()
        {
            super(new GMac(new GCMBlockCipher(new TwofishEngine())));
        }
    }

    public static class Poly1305
        extends BaseMac
    {
        public Poly1305()
        {
            super(new org.bouncycastle.crypto.macs.Poly1305(new TwofishEngine()));
        }
    }

    public static class Poly1305KeyGen
        extends BaseKeyGenerator
    {
        public Poly1305KeyGen()
        {
            super("Poly1305-Twofish", 256, new Poly1305KeyGenerator());
        }
    }

    /**
     * PBEWithSHAAndTwofish-CBC
     */
    static public class PBEWithSHAKeyFactory
        extends PBESecretKeyFactory
    {
        public PBEWithSHAKeyFactory()
        {
            super("PBEwithSHAandTwofish-CBC", null, true, PKCS12, SHA1, 256, 128);
        }
    }

    /**
     * PBEWithSHAAndTwofish-CBC
     */
    static public class PBEWithSHA
        extends BaseBlockCipher
    {
        public PBEWithSHA()
        {
            super(new CBCBlockCipher(new TwofishEngine()));
        }
    }

    public static class AlgParams
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "Twofish IV";
        }
    }

    public static class Mappings
        extends SymmetricAlgorithmProvider
    {
        private static final String PREFIX = Twofish.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("Cipher.Twofish", PREFIX + "$ECB");
            provider.addAlgorithm("KeyGenerator.Twofish", PREFIX + "$KeyGen");
            provider.addAlgorithm("AlgorithmParameters.Twofish", PREFIX + "$AlgParams");

            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.PBEWITHSHAANDTWOFISH", "PKCS12PBE");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.PBEWITHSHAANDTWOFISH-CBC", "PKCS12PBE");
            provider.addAlgorithm("Cipher.PBEWITHSHAANDTWOFISH-CBC",  PREFIX + "$PBEWithSHA");
            provider.addAlgorithm("SecretKeyFactory.PBEWITHSHAANDTWOFISH-CBC", PREFIX + "$PBEWithSHAKeyFactory");

            addGMacAlgorithm(provider, "Twofish", PREFIX + "$GMAC", PREFIX + "$KeyGen");
            addPoly1305Algorithm(provider, "Twofish", PREFIX + "$Poly1305", PREFIX + "$Poly1305KeyGen");
        }
    }
}
