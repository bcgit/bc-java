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

    private static SecureRandom secureRandom = new SecureRandom();

    public static class Default
        extends SecureRandomSpi
    {
        private SecureRandom random = new SP800SecureRandomBuilder(secureRandom, true)
            .setPersonalizationString(generateDefaultPersonalizationString(secureRandom))
            .buildHash(new SHA512Digest(), secureRandom.generateSeed(32), true);

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
            return secureRandom.generateSeed(numBytes);
        }
    }

    public static class NonceAndIV
        extends SecureRandomSpi
    {
        private SecureRandom random = new SP800SecureRandomBuilder(secureRandom, true)
            .setPersonalizationString(generateNonceIVPersonalizationString(secureRandom))
            .buildHash(new SHA512Digest(), secureRandom.generateSeed(32), false);

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
            return secureRandom.generateSeed(numBytes);
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
            Pack.longToBigEndian(Thread.currentThread().getId()), Pack.longToBigEndian(System.currentTimeMillis()));
    }

    private static byte[] generateNonceIVPersonalizationString(SecureRandom random)
    {
        return Arrays.concatenate(Strings.toByteArray("Nonce"), random.generateSeed(16),
            Pack.longToLittleEndian(Thread.currentThread().getId()), Pack.longToLittleEndian(System.currentTimeMillis()));
    }
}
