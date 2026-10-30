package org.bouncycastle.jcajce.provider.symmetric;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseStreamCipher;
import org.bouncycastle.jcajce.provider.symmetric.util.ChaCha20SpecUtil;
import org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;
import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;
import org.bouncycastle.jcajce.spec.BCChaCha20ParameterSpec;

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

    /**
     * ChaCha20 as defined in RFC 8439. Besides an IvParameterSpec carrying the nonce, which starts the key
     * stream at block 0, this accepts a BCChaCha20ParameterSpec or, from Java 11, the JDK's
     * ChaCha20ParameterSpec, which also give the initial block counter.
     */
    public static class Base7539
        extends BaseStreamCipher
    {
        private final ChaCha7539Engine engine;

        // the key stream position given by the initial block counter, returned to after every doFinal
        private long initialPosition;

        public Base7539()
        {
            this(new ChaCha7539Engine());
        }

        private Base7539(ChaCha7539Engine engine)
        {
            super(engine, 12);

            this.engine = engine;
        }

        protected void engineInit(
            int                     opmode,
            Key                     key,
            AlgorithmParameterSpec  params,
            SecureRandom            random)
            throws InvalidKeyException, InvalidAlgorithmParameterException
        {
            initialPosition = 0;

            BCChaCha20ParameterSpec counterSpec;
            if (params instanceof BCChaCha20ParameterSpec)
            {
                counterSpec = (BCChaCha20ParameterSpec)params;
            }
            else
            {
                counterSpec = ChaCha20SpecUtil.toBCChaCha20Spec(params);
            }

            if (counterSpec == null)
            {
                super.engineInit(opmode, key, params, random);
                return;
            }

            super.engineInit(opmode, key, new IvParameterSpec(counterSpec.getNonce()), random);

            // the counter is unsigned: a negative int addresses one of the blocks from 2^31 to 2^32 - 1
            initialPosition = (counterSpec.getCounter() & 0xFFFFFFFFL) * 64;
            restorePosition();
        }

        protected AlgorithmParameters engineGetParameters()
        {
            // AlgorithmParameters cannot carry the counter, and parameters without it would give the wrong key stream
            if (initialPosition != 0)
            {
                return null;
            }

            return super.engineGetParameters();
        }

        protected byte[] engineDoFinal(
            byte[]  input,
            int     inputOffset,
            int     inputLen)
        {
            byte[] output = super.engineDoFinal(input, inputOffset, inputLen);

            restorePosition();

            return output;
        }

        protected int engineDoFinal(
            byte[]  input,
            int     inputOffset,
            int     inputLen,
            byte[]  output,
            int     outputOffset)
            throws ShortBufferException
        {
            int outputLen = super.engineDoFinal(input, inputOffset, inputLen, output, outputOffset);

            restorePosition();

            return outputLen;
        }

        // init, and BaseStreamCipher's doFinal, leave the engine at block 0
        private void restorePosition()
        {
            if (initialPosition != 0)
            {
                engine.skip(initialPosition);
            }
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
