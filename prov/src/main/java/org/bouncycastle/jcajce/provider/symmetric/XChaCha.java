package org.bouncycastle.jcajce.provider.symmetric;

import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.engines.XChaCha20Engine;
import org.bouncycastle.crypto.modes.XChaCha20Poly1305;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseStreamCipher;
import org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;
import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

public final class XChaCha
{
    private XChaCha()
    {
    }

    public static class Base
        extends BaseStreamCipher
    {
        public Base()
        {
            super(new XChaCha20Engine(), 24);
        }
    }

    public static class BaseXC20P1305
        extends BaseBlockCipher
    {
        public BaseXC20P1305()
        {
            super(new XChaCha20Poly1305(), true, 24);
        }
    }

    public static class KeyGen
        extends BaseKeyGenerator
    {
        public KeyGen()
        {
            super("XChaCha20", 256, new CipherKeyGenerator());
        }
    }

    public static class AlgParams
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "XChaCha20 IV";
        }
    }

    public static class AlgParamsXC1305
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "XChaCha20-Poly1305 IV";
        }
    }

    public static class Mappings
        extends AlgorithmProvider
    {
        private static final String PREFIX = XChaCha.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("Cipher.XCHACHA20", PREFIX + "$Base");
            provider.addAlgorithm("KeyGenerator.XCHACHA20", PREFIX + "$KeyGen");
            provider.addAlgorithm("AlgorithmParameters.XCHACHA20", PREFIX + "$AlgParams");

            provider.addAlgorithm("Cipher.XCHACHA20-POLY1305", PREFIX + "$BaseXC20P1305");
            provider.addAlgorithm("AlgorithmParameters.XCHACHA20-POLY1305", PREFIX + "$AlgParamsXC1305");
            provider.addAlgorithm("Alg.Alias.KeyGenerator.XCHACHA20-POLY1305", "XCHACHA20");
        }
    }
}
