package org.bouncycastle.jcajce.provider.symmetric;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseStreamCipher;
import org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;
import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

public final class ChaCha
{
    private ChaCha()
    {
    }
    
    public static class Base
        extends BaseStreamCipher
    {
        public Base()
        {
            super(new ChaChaEngine(), 8);
        }
    }

    public static class KeyGen
        extends BaseKeyGenerator
    {
        public KeyGen()
        {
            super("ChaCha", 128, new CipherKeyGenerator());
        }
    }

    public static class Base7539
        extends BaseStreamCipher
    {
        public Base7539()
        {
            super(new ChaCha7539Engine(), 12);
        }
    }

    public static class BaseCC20P1305
        extends BaseBlockCipher
    {
        public BaseCC20P1305()
        {
            super(new ChaCha20Poly1305(), true, 12);
        }
    }

    public static class KeyGen7539
        extends BaseKeyGenerator
    {
        public KeyGen7539()
        {
            super("ChaCha7539", 256, new CipherKeyGenerator());
        }
    }

    public static class AlgParams
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "ChaCha7539 IV";
        }
    }

    public static class AlgParamsCC1305
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "ChaCha20-Poly1305 IV";
        }
    }

    public static class Mappings
        extends AlgorithmProvider
    {
        private static final String PREFIX = ChaCha.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {

            provider.addAlgorithm("Cipher.CHACHA", PREFIX + "$Base");
            provider.addAlgorithm("KeyGenerator.CHACHA", PREFIX + "$KeyGen");

            provider.addAlgorithm("Cipher.CHACHA7539", PREFIX + "$Base7539");
            provider.addAlgorithm("KeyGenerator.CHACHA7539", PREFIX + "$KeyGen7539");
            provider.addAlgorithm("AlgorithmParameters.CHACHA7539", PREFIX + "$AlgParams");
            provider.addAlgorithm("Alg.Alias.Cipher.CHACHA20", "CHACHA7539");
            provider.addAlgorithm("Alg.Alias.KeyGenerator.CHACHA20", "CHACHA7539");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.CHACHA20", "CHACHA7539");

            provider.addAlgorithm("Alg.Alias.KeyGenerator.CHACHA20-POLY1305", "CHACHA7539");
            provider.addAlgorithm("Alg.Alias.KeyGenerator." + PKCSObjectIdentifiers.id_alg_AEADChaCha20Poly1305, "CHACHA7539");
            provider.addAlgorithm("Cipher.CHACHA20-POLY1305", PREFIX + "$BaseCC20P1305");
            provider.addAlgorithm("AlgorithmParameters.CHACHA20-POLY1305", PREFIX + "$AlgParamsCC1305");
            provider.addAlgorithm("Alg.Alias.Cipher." + PKCSObjectIdentifiers.id_alg_AEADChaCha20Poly1305, "CHACHA20-POLY1305");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + PKCSObjectIdentifiers.id_alg_AEADChaCha20Poly1305, "CHACHA20-POLY1305");
            provider.addAlgorithm("Alg.Alias.Cipher.OID." + PKCSObjectIdentifiers.id_alg_AEADChaCha20Poly1305, "CHACHA20-POLY1305");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.OID." + PKCSObjectIdentifiers.id_alg_AEADChaCha20Poly1305, "CHACHA20-POLY1305");
        }
    }
}
