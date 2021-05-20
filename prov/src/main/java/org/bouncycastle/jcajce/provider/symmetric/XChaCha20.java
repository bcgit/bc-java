package org.bouncycastle.jcajce.provider.symmetric;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.crypto.engines.XChaCha20Engine;
import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.modes.XChaCha20Poly1305;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseStreamCipher;
import org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;
import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

public final class XChaCha20
{
    private XChaCha20()
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

    public static class KeyGen
        extends BaseKeyGenerator
    {
        public KeyGen()
        {
            super("XChaCha20", 256, new CipherKeyGenerator());
        }
    }

    public static class BaseXCC20P1305
        extends BaseBlockCipher
    {
        public BaseXCC20P1305()
        {
            super(new XChaCha20Poly1305(), true, 24);
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

    public static class AlgParamsXCC1305
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
        private static final String PREFIX = XChaCha20.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {

            provider.addAlgorithm("Cipher.XCHACHA20", PREFIX + "$Base");
            provider.addAlgorithm("KeyGenerator.XCHACHA20", PREFIX + "$KeyGen");
            provider.addAlgorithm("AlgorithmParameters.XCHACHA20", PREFIX + "$AlgParams");

            provider.addAlgorithm("Alg.Alias.KeyGenerator.XCHACHA20-POLY1305", "XCHACHA20");

            provider.addAlgorithm("Cipher.XCHACHA20-POLY1305", PREFIX + "$BaseXCC20P1305");
            provider.addAlgorithm("AlgorithmParameters.XCHACHA20-POLY1305", PREFIX + "$AlgParamsXCC1305");
        }
    }
}
