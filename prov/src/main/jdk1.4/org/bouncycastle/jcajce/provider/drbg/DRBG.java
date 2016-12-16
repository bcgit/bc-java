package org.bouncycastle.jcajce.provider.drbg;

import java.security.SecureRandom;
import java.security.SecureRandomSpi;

import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.prng.SP800SecureRandomBuilder;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Strings;

public class DRBG
{
    private static final String PREFIX = DRBG.class.getName();

    public static class Default
        extends SecureRandomSpi
    {
        private SecureRandom randomSource = new SecureRandom();   // needs to be done late, can't use static
        private SecureRandom random = new SP800SecureRandomBuilder(randomSource, true)
            .setPersonalizationString(generateDefaultPersonalizationString(randomSource))
            .buildHash(new SHA512Digest(), randomSource.generateSeed(32), true);

        protected void engineSetSeed(byte[] bytes)
        {
            random.setSeed(bytes);
        }

        protected void engineNextBytes(byte[] bytes)
        {
            random.nextBytes(bytes);
        }

        protected byte[] engineGenerateSeed(int numBytes)
        {
            return randomSource.generateSeed(numBytes);
        }
    }

    public static class NonceAndIV
        extends SecureRandomSpi
    {
        private SecureRandom randomSource = new SecureRandom();  // needs to be done late, can't use static
        private SecureRandom random = new SP800SecureRandomBuilder(randomSource, true)
            .setPersonalizationString(generateNonceIVPersonalizationString(randomSource))
            .buildHash(new SHA512Digest(), randomSource.generateSeed(32), false);

        protected void engineSetSeed(byte[] bytes)
        {
            random.setSeed(bytes);
        }

        protected void engineNextBytes(byte[] bytes)
        {
            random.nextBytes(bytes);
        }

        protected byte[] engineGenerateSeed(int numBytes)
        {
            return randomSource.generateSeed(numBytes);
        }
    }

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("SecureRandom.DEFAULT", PREFIX + "$Default");
            provider.addAlgorithm("SecureRandom.NONCEANDIV", PREFIX + "$NonceAndIV");
        }
    }

    private static byte[] generateDefaultPersonalizationString(SecureRandom random)
    {
        return Arrays.concatenate(Strings.toByteArray("Default"), random.generateSeed(16),
            Strings.toByteArray(Thread.currentThread().toString()), Pack.longToBigEndian(System.currentTimeMillis()));
    }

    private static byte[] generateNonceIVPersonalizationString(SecureRandom random)
    {
        return Arrays.concatenate(Strings.toByteArray("Nonce"), random.generateSeed(16),
            Strings.toByteArray(Thread.currentThread().toString()), Pack.longToLittleEndian(System.currentTimeMillis()));
    }
}
