package org.bouncycastle.jcajce.provider.symmetric;

import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.engines.Zuc128Engine;
import org.bouncycastle.crypto.engines.Zuc256Engine;
import org.bouncycastle.crypto.macs.Zuc128Mac;
import org.bouncycastle.crypto.macs.Zuc256Mac;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseStreamCipher;
import org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;

public class Zuc
{
    private Zuc()
    {
    }

    public static class Zuc128
        extends BaseStreamCipher
    {
        public Zuc128()
        {
            super(new Zuc128Engine(), 16, 128);
        }
    }

    public static class Zuc256
        extends BaseStreamCipher
    {
        public Zuc256()
        {
            super(new Zuc256Engine(), 25, 256);
        }
    }

    public static class KeyGen128
        extends BaseKeyGenerator
    {
        public KeyGen128()
        {
            super("ZUC128", 128, new CipherKeyGenerator());
        }
    }

    public static class KeyGen256
        extends BaseKeyGenerator
    {
        public KeyGen256()
        {
            super("ZUC256", 256, new CipherKeyGenerator());
        }
    }

    public static class AlgParams
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "Zuc IV";
        }
    }

    public static class ZucMac128
        extends BaseMac
    {
        public ZucMac128()
        {
            super(new Zuc128Mac());
        }
    }

    public static class ZucMac256
        extends BaseMac
    {
        public ZucMac256()
        {
            super(new Zuc256Mac(128));
        }
    }

    public static class ZucMac256_64
        extends BaseMac
    {
        public ZucMac256_64()
        {
            super(new Zuc256Mac(64));
        }
    }

    public static class ZucMac256_32
        extends BaseMac
    {
        public ZucMac256_32()
        {
            super(new Zuc256Mac(32));
        }
    }

    public static class Mappings
        extends SymmetricAlgorithmProvider
    {
        private static final String PREFIX = Zuc.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("Cipher.ZUC-128", PREFIX + "$Zuc128");
            provider.addAlgorithm("KeyGenerator.ZUC-128", PREFIX + "$KeyGen128");
            provider.addAlgorithm("AlgorithmParameters.ZUC-128", PREFIX + "$AlgParams");

            provider.addAlgorithm("Cipher.ZUC-256", PREFIX + "$Zuc256");
            provider.addAlgorithm("KeyGenerator.ZUC-256", PREFIX + "$KeyGen256");
            provider.addAlgorithm("AlgorithmParameters.ZUC-256", PREFIX + "$AlgParams");

            provider.addAlgorithm("Mac.ZUC-128",  PREFIX + "$ZucMac128");
            provider.addAlgorithm("Mac.ZUC-256",  PREFIX + "$ZucMac256");
            provider.addAlgorithm("Alg.Alias.Mac.ZUC-256-128", "ZUC-256");
            provider.addAlgorithm("Mac.ZUC-256-64", PREFIX + "$ZucMac256_64");
            provider.addAlgorithm("Mac.ZUC-256-32", PREFIX + "$ZucMac256_32");
        }
    }
}
