package org.bouncycastle.jcajce.provider.drbg;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;
import java.security.Security;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.crypto.prng.EntropySourceProvider;
import org.bouncycastle.crypto.prng.SP800SecureRandom;
import org.bouncycastle.crypto.prng.SP800SecureRandomBuilder;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.ClassUtil;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Strings;

/**
 * <b>DRBG Configuration</b><br/>
 * <p>
 * org.bouncycastle.drbg.gather_pause_secs - is to stop the entropy collection thread from grabbing all
 * available entropy on the system. The original motivation for the hybrid infrastructure was virtual machines
 * sometimes produce very few bits of entropy a second, the original approach (which "worked" at least for BC) was
 * to just read on the second thread and allow things to progress around it, but it did tend to hog the system
 * if other processes were using /dev/random. By default the thread will pause for 5 seconds between 64 bit reads,
 * increasing this time will reduce the demands on the system entropy pool. Ideally the pause will be set to large
 * enough to allow everyone to work together, but small enough to ensure the provider's DRBG is being regularly
 * reseeded.
 * </p>
 * <p>
 * org.bouncycastle.drbg.entropysource - is the class name for an implementation of EntropySourceProvider.
 * For example, one could be provided which just reads directly from /dev/random and the extra infrastructure used here
 * could be avoided.
 * </p>
 * <p>
 * org.bouncycastle.drbg.entropy_thread - if true the provider will start a single daemon thread for handling entropy requests,
 * rather than starting a thread periodically when samples are required.
 * </p>
 */
public class DRBG
{
    private static final String PREFIX = DRBG.class.getName();

    // {"Provider class name","SecureRandomSpi class name"}
    private static final String[][] initialEntropySourceNames = new String[][]
        {
            // Normal JVM
            {"sun.security.provider.Sun", "sun.security.provider.SecureRandom"},
            // Apache harmony
            {"org.apache.harmony.security.provider.crypto.CryptoProvider", "org.apache.harmony.security.provider.crypto.SHA1PRNG_SecureRandomImpl"},
            // Android.
            {"com.android.org.conscrypt.OpenSSLProvider", "com.android.org.conscrypt.OpenSSLRandom"},
            {"org.conscrypt.OpenSSLProvider", "org.conscrypt.OpenSSLRandom"},
        };

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

    private static EntropyDaemon entropyDaemon = null;
    private static Thread entropyThread = null;

    static
    {
        entropyDaemon = new EntropyDaemon();
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

    public static class Default
        extends SecureRandomSpi
    {
        private static final SecureRandom random = createBaseRandom(true);

        public Default()
        {
        }

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
            return random.generateSeed(numBytes);
        }
    }

    public static class NonceAndIV
        extends SecureRandomSpi
    {
        private static final SecureRandom random = createBaseRandom(false);

        public NonceAndIV()
        {
        }

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
            return random.generateSeed(numBytes);
        }
    }

    private static SecureRandom createBaseRandom(boolean isPredictionResistant)
    {
        if (Properties.getPropertyValue("org.bouncycastle.drbg.entropysource") != null)
        {
            EntropySourceProvider entropyProvider = createEntropySource();

            EntropySource initSource = entropyProvider.get(16 * 8);

            byte[] personalisationString = isPredictionResistant
                ? generateDefaultPersonalizationString(initSource.getEntropy())
                : generateNonceIVPersonalizationString(initSource.getEntropy());

            return new SP800SecureRandomBuilder(entropyProvider)
                .setPersonalizationString(personalisationString)
                .buildHash(new SHA512Digest(), initSource.getEntropy(), isPredictionResistant);
        }
        else if (Properties.isOverrideSet("org.bouncycastle.drbg.entropy_thread"))
        {
            synchronized (entropyDaemon)
            {
                if (entropyThread == null)
                {
                    entropyThread = new Thread(entropyDaemon, "BC Entropy Daemon");
                    entropyThread.setDaemon(true);
                    entropyThread.start();
                }
            }
            EntropySource source = new HybridEntropySource(entropyDaemon, 256);

            byte[] personalisationString = isPredictionResistant
                ? generateDefaultPersonalizationString(source.getEntropy())
                : generateNonceIVPersonalizationString(source.getEntropy());

            return new SP800SecureRandomBuilder(new EntropySourceProvider()
            {
                public EntropySource get(int bitsRequired)
                {
                    return new HybridEntropySource(entropyDaemon, bitsRequired);
                }
            })
                .setPersonalizationString(personalisationString)
                .buildHash(new SHA512Digest(), source.getEntropy(), isPredictionResistant);
        }
        else
        {
            EntropySource initSource = new OneShotHybridEntropySource(256);

            byte[] personalisationString = isPredictionResistant
                ? generateDefaultPersonalizationString(initSource.getEntropy())
                : generateNonceIVPersonalizationString(initSource.getEntropy());

            return new SP800SecureRandomBuilder(new EntropySourceProvider()
            {
                public EntropySource get(int bitsRequired)
                {
                    return new OneShotHybridEntropySource(bitsRequired);
                }
            })
                .setPersonalizationString(personalisationString)
                .buildHash(new SHA512Digest(), initSource.getEntropy(), isPredictionResistant);
        }
    }

    // unfortunately new SecureRandom() can cause a regress and it's the only reliable way of getting access
    // to the JVM's seed generator.
    private static EntropySourceProvider createInitialEntropySource()
    {
        boolean hasGetInstanceStrong = AccessController.doPrivileged(new PrivilegedAction<Boolean>()
        {
            public Boolean run()
            {
                try
                {
                    Class def = SecureRandom.class;

                    return def.getMethod("getInstanceStrong") != null;
                }
                catch (Exception e)
                {
                    return false;
                }
            }
        });

        if (hasGetInstanceStrong)
        {
            SecureRandom strong = AccessController.doPrivileged(new PrivilegedAction<SecureRandom>()
            {
                public SecureRandom run()
                {
                    try
                    {
                        return (SecureRandom)SecureRandom.class.getMethod("getInstanceStrong").invoke(null);
                    }
                    catch (Exception e)
                    {
                        return new CoreSecureRandom(findSource());
                    }
                }
            });

            return new IncrementalEntropySourceProvider(strong, true);
        }
        else
        {
            return new IncrementalEntropySourceProvider(new CoreSecureRandom(findSource()), true);
        }
    }

    private static EntropySourceProvider createCoreEntropySourceProvider()
    {
        String source = AccessController.doPrivileged(new PrivilegedAction<String>()
        {
            public String run()
            {
                return Security.getProperty("securerandom.source");
            }
        });

        if (source == null)
        {
            return createInitialEntropySource();
        }
        else
        {
            try
            {
                return new URLSeededEntropySourceProvider(new URL(source));
            }
            catch (Exception e)
            {
                return createInitialEntropySource();
            }
        }
    }

    private static EntropySourceProvider createEntropySource()
    {
        final String sourceClass = Properties.getPropertyValue("org.bouncycastle.drbg.entropysource");

        return AccessController.doPrivileged(new PrivilegedAction<EntropySourceProvider>()
        {
            public EntropySourceProvider run()
            {
                try
                {
                    Class clazz = ClassUtil.loadClass(DRBG.class, sourceClass);

                    return (EntropySourceProvider)clazz.newInstance();
                }
                catch (Exception e)
                {
                    throw new IllegalStateException("entropy source " + sourceClass + " not created: " + e.getMessage(), e);
                }
            }
        });
    }

    private static byte[] generateDefaultPersonalizationString(byte[] seed)
    {
        return Arrays.concatenate(Strings.toByteArray("Default"), seed,
            Pack.longToBigEndian(Thread.currentThread().getId()), Pack.longToBigEndian(System.currentTimeMillis()));
    }

    private static byte[] generateNonceIVPersonalizationString(byte[] seed)
    {
        return Arrays.concatenate(Strings.toByteArray("Nonce"), seed,
            Pack.longToLittleEndian(Thread.currentThread().getId()), Pack.longToLittleEndian(System.currentTimeMillis()));
    }

    private static class CoreSecureRandom
        extends SecureRandom
    {
        CoreSecureRandom(Object[] initialEntropySourceAndSpi)
        {
            super((SecureRandomSpi)initialEntropySourceAndSpi[1], (Provider)initialEntropySourceAndSpi[0]);
        }
    }

    private static void sleep(long ms)
        throws InterruptedException
    {
        if (ms != 0)
        {
            Thread.sleep(ms);
        }
    }

    private static class URLSeededEntropySourceProvider
        implements EntropySourceProvider
    {
        private final InputStream seedStream;

        URLSeededEntropySourceProvider(final URL url)
        {
            this.seedStream = AccessController.doPrivileged(new PrivilegedAction<InputStream>()
            {
                public InputStream run()
                {
                    try
                    {
                        return url.openStream();
                    }
                    catch (IOException e)
                    {
                        throw new IllegalStateException("unable to open random source");
                    }
                }
            });
        }

        private int privilegedRead(final byte[] data, final int off, final int len)
        {
            return AccessController.doPrivileged(new PrivilegedAction<Integer>()
            {
                public Integer run()
                {
                    try
                    {
                        return seedStream.read(data, off, len);
                    }
                    catch (IOException e)
                    {
                        throw new InternalError("unable to read random source");
                    }
                }
            });
        }

        public EntropySource get(final int bitsRequired)
        {
            return new IncrementalEntropySource()
            {
                private final int numBytes = (bitsRequired + 7) / 8;

                public boolean isPredictionResistant()
                {
                    return true;
                }

                public byte[] getEntropy()
                {
                    try
                    {
                        return getEntropy(0);
                    }
                    catch (InterruptedException e)
                    {
                        Thread.currentThread().interrupt();
                        throw new IllegalStateException("initial entropy fetch interrupted"); // should never happen
                    }
                }

                public byte[] getEntropy(long pause)
                    throws InterruptedException
                {
                    byte[] data = new byte[numBytes];

                    int off = 0;
                    int len;

                    while (off != data.length && (len = privilegedRead(data, off, data.length - off)) > -1)
                    {
                        off += len;
                        sleep(pause);
                    }

                    if (off != data.length)
                    {
                        throw new InternalError("unable to fully read random source");
                    }

                    return data;
                }

                public int entropySize()
                {
                    return bitsRequired;
                }
            };
        }
    }

    private static class HybridEntropySource
        implements EntropySource
    {
        private final AtomicBoolean seedAvailable = new AtomicBoolean(false);
        private final AtomicInteger samples = new AtomicInteger(0);

        private final SP800SecureRandom drbg;
        private final SignallingEntropySource entropySource;
        private final int bytesRequired;
        private final byte[] additionalInput = Pack.longToBigEndian(System.currentTimeMillis());

        HybridEntropySource(final EntropyDaemon entropyDaemon, final int bitsRequired)
        {
            EntropySourceProvider entropyProvider = createCoreEntropySourceProvider();
            bytesRequired = (bitsRequired + 7) / 8;
            // remember for the seed generator we need the correct security strength for SHA-512
            entropySource = new SignallingEntropySource(entropyDaemon, seedAvailable, entropyProvider, 256);
            drbg = new SP800SecureRandomBuilder(new EntropySourceProvider()
            {
                public EntropySource get(final int bitsRequired)
                {
                    return entropySource;
                }
            })
                .setPersonalizationString(Strings.toByteArray("Bouncy Castle Hybrid Entropy Source"))
                .buildHMAC(new HMac(new SHA512Digest()), entropySource.getEntropy(), false);     // 32 byte nonce
        }

        public boolean isPredictionResistant()
        {
            return true;
        }

        public byte[] getEntropy()
        {
            byte[] entropy = new byte[bytesRequired];

            // after 128 samples we'll start to check if there is new seed material.
            if (samples.getAndIncrement() > 128)
            {
                if (seedAvailable.getAndSet(false))
                {
                    samples.set(0);
                    drbg.reseed(additionalInput);
                }
                else
                {
                    entropySource.schedule();
                }
            }

            drbg.nextBytes(entropy);

            return entropy;
        }

        public int entropySize()
        {
            return bytesRequired * 8;
        }

        private static class SignallingEntropySource
            implements IncrementalEntropySource
        {
            private final EntropyDaemon entropyDaemon;
            private final AtomicBoolean seedAvailable;
            private final IncrementalEntropySource entropySource;
            private final int byteLength;
            private final AtomicReference entropy = new AtomicReference();
            private final AtomicBoolean scheduled = new AtomicBoolean(false);

            SignallingEntropySource(EntropyDaemon entropyDaemon, AtomicBoolean seedAvailable, EntropySourceProvider baseRandom, int bitsRequired)
            {
                this.entropyDaemon = entropyDaemon;
                this.seedAvailable = seedAvailable;
                this.entropySource = (IncrementalEntropySource)baseRandom.get(bitsRequired);
                this.byteLength = (bitsRequired + 7) / 8;
            }

            public boolean isPredictionResistant()
            {
                return true;
            }

            public byte[] getEntropy()
            {
                try
                {
                    return getEntropy(0);
                }
                catch (InterruptedException e)
                {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("initial entropy fetch interrupted"); // should never happen
                }
            }

            public byte[] getEntropy(long pause)
                throws InterruptedException
            {
                byte[] seed = (byte[])entropy.getAndSet(null);

                if (seed == null || seed.length != byteLength)
                {
                    seed = entropySource.getEntropy(pause);
                }
                else
                {
                    scheduled.set(false);
                }

                return seed;
            }

            void schedule()
            {
                if (!scheduled.getAndSet(true))
                {
                    entropyDaemon.addTask(new EntropyGatherer(entropySource, seedAvailable, entropy));
                }
            }

            public int entropySize()
            {
                return byteLength * 8;
            }
        }
    }

    private static class OneShotHybridEntropySource
        implements EntropySource
    {
        private final AtomicBoolean seedAvailable = new AtomicBoolean(false);
        private final AtomicInteger samples = new AtomicInteger(0);

        private final SP800SecureRandom drbg;
        private final OneShotSignallingEntropySource entropySource;
        private final int bytesRequired;
        private final byte[] additionalInput = Pack.longToBigEndian(System.currentTimeMillis());

        OneShotHybridEntropySource(final int bitsRequired)
        {
            EntropySourceProvider entropyProvider = createCoreEntropySourceProvider();
            bytesRequired = (bitsRequired + 7) / 8;
            // remember for the seed generator we need the correct security strength for SHA-512
            entropySource = new OneShotSignallingEntropySource(seedAvailable, entropyProvider, 256);
            drbg = new SP800SecureRandomBuilder(new EntropySourceProvider()
            {
                public EntropySource get(final int bitsRequired)
                {
                    return entropySource;
                }
            })
                .setPersonalizationString(Strings.toByteArray("Bouncy Castle Hybrid Entropy Source"))
                .buildHMAC(new HMac(new SHA512Digest()), entropySource.getEntropy(), false);     // 32 byte nonce
        }

        public boolean isPredictionResistant()
        {
            return true;
        }

        public byte[] getEntropy()
        {
            byte[] entropy = new byte[bytesRequired];

            // after 1024 samples we'll start to check if there is new seed material,
            // we do this less often than with the daemon based one due to the overheads.
            if (samples.getAndIncrement() > 1024)
            {
                if (seedAvailable.getAndSet(false))
                {
                    samples.set(0);
                    drbg.reseed(additionalInput);
                }
                else
                {
                    entropySource.schedule();
                }
            }

            drbg.nextBytes(entropy);

            return entropy;
        }

        public int entropySize()
        {
            return bytesRequired * 8;
        }

        private static class OneShotSignallingEntropySource
            implements IncrementalEntropySource
        {
            private final AtomicBoolean seedAvailable;
            private final IncrementalEntropySource entropySource;
            private final int byteLength;
            private final AtomicReference entropy = new AtomicReference();
            private final AtomicBoolean scheduled = new AtomicBoolean(false);

            OneShotSignallingEntropySource(AtomicBoolean seedAvailable, EntropySourceProvider baseRandom, int bitsRequired)
            {
                this.seedAvailable = seedAvailable;
                this.entropySource = (IncrementalEntropySource)baseRandom.get(bitsRequired);
                this.byteLength = (bitsRequired + 7) / 8;
            }

            public boolean isPredictionResistant()
            {
                return true;
            }

            public byte[] getEntropy()
            {
                try
                {
                    return getEntropy(0);
                }
                catch (InterruptedException e)
                {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("initial entropy fetch interrupted"); // should never happen
                }
            }

            public byte[] getEntropy(long pause)
                throws InterruptedException
            {
                byte[] seed = (byte[])entropy.getAndSet(null);

                if (seed == null || seed.length != byteLength)
                {
                    seed = entropySource.getEntropy(pause);
                }
                else
                {
                    scheduled.set(false);
                }

                return seed;
            }

            void schedule()
            {
                if (!scheduled.getAndSet(true))
                {
                    Thread thread = new Thread(new EntropyGatherer(entropySource, seedAvailable, entropy));
                    thread.setDaemon(true);
                    thread.start();
                }
            }

            public int entropySize()
            {
                return byteLength * 8;
            }
        }
    }
}
