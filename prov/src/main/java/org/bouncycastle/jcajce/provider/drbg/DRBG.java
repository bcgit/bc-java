package org.bouncycastle.jcajce.provider.drbg;

import java.security.Provider;
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

    private static final String[][] initialEntropySourceNames = new String[][]{
        // Normal JVM
        {"sun.security.provider.Sun", "sun.security.provider.SecureRandom"},
        // Apache harmony
        {"org.apache.harmony.security.provider.crypto.CryptoProvider", "org.apache.harmony.security.provider.crypto.SHA1PRNG_SecureRandomImpl"},
        // {"Provider class name","SecureRandomSpi class name"}
        //            // Android.
        {"com.android.org.conscrypt.OpenSSLProvider", "com.android.org.conscrypt.OpenSSLRandom"},
        {"org.conscrypt.OpenSSLProvider", "org.conscrypt.OpenSSLRandom"},
    };

    private static final Object[] initialEntropySourceAndSpi = findSource();

    // Cascade through providers looking for match.
    private final static Object[] findSource()
    {
        for (int t = 0; t < initialEntropySourceNames.length; t++)
        {
            String[] pair = initialEntropySourceNames[t];
            try
            {
                Object[] r = new Object[]{Class.forName(pair[0]).newInstance(), Class.forName(pair[1]).newInstance()};

                return r;
            }
            catch (Throwable ex)
            {
                continue;
            }
        }

        return null;
    }

    private static class CoreSecureRandom
        extends SecureRandom
    {
        CoreSecureRandom()
        {
            super((SecureRandomSpi)initialEntropySourceAndSpi[1], (Provider)initialEntropySourceAndSpi[0]);
        }
    }

    // unfortunately new SecureRandom() can cause a regress and it's the only reliable way of getting access
    // to the JVM's seed generator.
    private static SecureRandom createInitialEntropySource()
    {
        if (initialEntropySourceAndSpi != null)
        {
            return new CoreSecureRandom();
        }
        else
        {
            return new SecureRandom();  // we're desperate, it's worth a try.
        }
    }

    public static class Default
        extends SecureRandomSpi
    {
        private SecureRandom randomSource = createInitialEntropySource();   // needs to be done late, can't use static
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
        private SecureRandom randomSource = createInitialEntropySource();
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
            Pack.longToBigEndian(Thread.currentThread().getId()), Pack.longToBigEndian(System.currentTimeMillis()));
    }

    private static byte[] generateNonceIVPersonalizationString(SecureRandom random)
    {
        return Arrays.concatenate(Strings.toByteArray("Nonce"), random.generateSeed(16),
            Pack.longToLittleEndian(Thread.currentThread().getId()), Pack.longToLittleEndian(System.currentTimeMillis()));
    }
}
