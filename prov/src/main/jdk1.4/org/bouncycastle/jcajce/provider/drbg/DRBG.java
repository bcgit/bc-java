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
import org.bouncycastle.util.Integers;

/**
 * <b>DRBG Configuration</b><br/>
 * <p>org.bouncycastle.drbg.gather_pause_secs - is to stop the entropy collection thread from grabbing all
 * available entropy on the system. The original motivation for the hybrid infrastructure was virtual machines
 * sometimes produce very few bits of entropy a second, the original approach (which "worked" at least for BC) was
 * to just read on the second thread and allow things to progress around it, but it did tend to hog the system
 * if other processes were using /dev/random. By default the thread will pause for 5 seconds between 64 bit reads,
 * increasing this time will reduce the demands on the system entropy pool. Ideally the pause will be set to large
 * enough to allow everyone to work together, but small enough to ensure the provider's DRBG is being regularly
 * reseeded.
 * </p>
 * <p>org.bouncycastle.drbg.entropysource - is the class name for an implementation of EntropySourceProvider.
 * For example, one could be provided which just reads directly from /dev/random and the extra infrastructure used here
 * could be avoided.</p>
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

    private static class CoreSecureRandom
        extends SecureRandom
    {
        CoreSecureRandom(Object[] initialEntropySourceAndSpi)
        {
            super((SecureRandomSpi)initialEntropySourceAndSpi[1], (Provider)initialEntropySourceAndSpi[0]);
        }
    }

    // unfortunately new SecureRandom() can cause a regress and it's the only reliable way of getting access
    // to the JVM's seed generator.
    private static SecureRandom createInitialEntropySource()
    {
        return createCoreSecureRandom();
    }

    private static SecureRandom createCoreSecureRandom()
    {
        if (Security.getProperty("securerandom.source") == null)
        {
            return new CoreSecureRandom(findSource());
        }
        else
        {
            try
            {
                String source = Security.getProperty("securerandom.source");

                return new URLSeededSecureRandom(new URL(source));
            }
            catch (Exception e)
            {
                return new CoreSecureRandom(findSource());
            }
        }
    }

    private static EntropySourceProvider createEntropySource()
    {
        final String sourceClass = Properties.getPropertyValue("org.bouncycastle.drbg.entropysource");

        return (EntropySourceProvider)AccessController.doPrivileged(new PrivilegedAction()
        {
            public Object run()
            {
                try
                {
                    Class clazz = ClassUtil.loadClass(DRBG.class, sourceClass);

                    return clazz.newInstance();
                }
                catch (Exception e)
                {
                    throw new IllegalStateException("entropy source " + sourceClass + " not created: " + e.getMessage());
                }
            }
        });
    }

    private static SecureRandom createBaseRandom(boolean isPredictionResistant)
    {
        if (Properties.getPropertyValue("org.bouncycastle.drbg.entropysource") != null)
        {
            EntropySourceProvider entropyProvider = createEntropySource();

            EntropySource initSource = entropyProvider.get(16 * 8);

            byte[] personalisationString = isPredictionResistant ? generateDefaultPersonalizationString(initSource.getEntropy())
                                                                 : generateNonceIVPersonalizationString(initSource.getEntropy());

            return new SP800SecureRandomBuilder(entropyProvider)
                                .setPersonalizationString(personalisationString)
                                .buildHash(new SHA512Digest(), Arrays.concatenate(initSource.getEntropy(), initSource.getEntropy()), isPredictionResistant);
        }
        else
        {
            SecureRandom randomSource = new HybridSecureRandom();   // needs to be done late, can't use static

            byte[] personalisationString = isPredictionResistant ? generateDefaultPersonalizationString(randomSource.generateSeed(16))
                                                                 : generateNonceIVPersonalizationString(randomSource.generateSeed(16));

            return new SP800SecureRandomBuilder(randomSource, true)
                .setPersonalizationString(personalisationString)
                .buildHash(new SHA512Digest(), randomSource.generateSeed(32), isPredictionResistant);
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

    private static byte[] generateDefaultPersonalizationString(byte[] seed)
    {
        return Arrays.concatenate(Strings.toByteArray("Default"), seed,
            Strings.toByteArray(Thread.currentThread().toString()), Pack.longToBigEndian(System.currentTimeMillis()));
    }

    private static byte[] generateNonceIVPersonalizationString(byte[] seed)
    {
        return Arrays.concatenate(Strings.toByteArray("Nonce"), seed,
            Strings.toByteArray(Thread.currentThread().toString()), Pack.longToLittleEndian(System.currentTimeMillis()));
    }

    private static class HybridRandomProvider
        extends Provider
    {
        protected HybridRandomProvider()
        {
            super("BCHEP", 1.0, "Bouncy Castle Hybrid Entropy Provider");
        }
    }

    private static class URLSeededSecureRandom
        extends SecureRandom
    {
        private final InputStream seedStream;

        URLSeededSecureRandom(final URL url)
        {
            super(null, new HybridRandomProvider());

            this.seedStream = (InputStream)AccessController.doPrivileged(new PrivilegedAction<InputStream>()
            {
                public Object run()
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

        public void setSeed(byte[] seed)
        {
            // ignore
        }

        public void setSeed(long seed)
        {
            // ignore
        }

        public byte[] generateSeed(int numBytes)
        {
            synchronized (this)
            {
                byte[] data = new byte[numBytes];

                int off = 0;
                int len;

                while (off != data.length && (len = privilegedRead(data, off, data.length - off)) > -1)
                {
                    off += len;
                }

                if (off != data.length)
                {
                    throw new InternalError("unable to fully read random source");
                }

                return data;
            }
        }

        private int privilegedRead(final byte[] data, final int off, final int len)
        {
            return ((Integer)AccessController.doPrivileged(new PrivilegedAction<Integer>()
            {
                public Object run()
                {
                    try
                    {
                        return Integers.valueOf(seedStream.read(data, off, len));
                    }
                    catch (IOException e)
                    {
                        throw new InternalError("unable to read random source");
                    }
                }
            })).intValue();
        }
    }

    private static class HybridSecureRandom
        extends SecureRandom
    {
        private final AtomicBoolean seedAvailable = new AtomicBoolean(false);
        private final AtomicInteger samples = new AtomicInteger(0);
        private final SecureRandom baseRandom = createInitialEntropySource();

        private final SP800SecureRandom drbg;

        HybridSecureRandom()
        {
            super(null, new HybridRandomProvider());
            drbg = new SP800SecureRandomBuilder(new EntropySourceProvider()
                {
                    public EntropySource get(final int bitsRequired)
                    {
                        return new SignallingEntropySource(bitsRequired);
                    }
                })
                .setPersonalizationString(Strings.toByteArray("Bouncy Castle Hybrid Entropy Source"))
                .buildHMAC(new HMac(new SHA512Digest()), baseRandom.generateSeed(32), false);     // 32 byte nonce
        }

        public void setSeed(byte[] seed)
        {
            if (drbg != null)
            {
                drbg.setSeed(seed);
            }
        }

        public void setSeed(long seed)
        {
            if (drbg != null)
            {
                drbg.setSeed(seed);
            }
        }

        public byte[] generateSeed(int numBytes)
        {
            byte[] data = new byte[numBytes];

            // after 20 samples we'll start to check if there is new seed material.
            if (samples.getAndIncrement() > 20)
            {
                if (seedAvailable.getAndSet(false))
                {
                    samples.set(0);
                    drbg.reseed((byte[])null);    // need for Java 1.9
                }
            }

            drbg.nextBytes(data);

            return data;
        }

        private class SignallingEntropySource
            implements EntropySource
        {
            private final int byteLength;
            private final AtomicReference entropy = new AtomicReference();
            private final AtomicBoolean scheduled = new AtomicBoolean(false);

            SignallingEntropySource(int bitsRequired)
            {
                this.byteLength = (bitsRequired + 7) / 8;
            }

            public boolean isPredictionResistant()
            {
                return true;
            }

            public byte[] getEntropy()
            {
                byte[] seed = (byte[])entropy.getAndSet(null);

                if (seed == null || seed.length != byteLength)
                {
                    seed = baseRandom.generateSeed(byteLength);
                }
                else
                {
                    scheduled.set(false);
                }

                if (!scheduled.getAndSet(true))
                {
                    Thread gathererThread = new Thread(new EntropyGatherer(byteLength));
                    gathererThread.setDaemon(true);
                    gathererThread.start();
                }

                return seed;
            }

            public int entropySize()
            {
                return byteLength * 8;
            }

            private class EntropyGatherer
                implements Runnable
            {
                private final int numBytes;

                EntropyGatherer(int numBytes)
                {
                    this.numBytes = numBytes;
                }

                private void sleep(long ms)
                {
                    try
                    {
                        Thread.sleep(ms);
                    }
                    catch (InterruptedException e)
                    {
                        Thread.currentThread().interrupt();
                    }
                }

                public void run()
                {
                    long ms;
                    String pause = Properties.getPropertyValue("org.bouncycastle.drbg.gather_pause_secs");

                    if (pause != null)
                    {
                        try
                        {
                            ms = Long.parseLong(pause) * 1000;
                        }
                        catch (Exception e)
                        {
                            ms = 5000;
                        }
                    }
                    else
                    {
                        ms = 5000;
                    }

                    byte[] seed = new byte[numBytes];
                    for (int i = 0; i < byteLength / 8; i++)
                    {
                        // we need to be mindful that we may not be the only thread/process looking for entropy
                        sleep(ms);
                        byte[] rn = baseRandom.generateSeed(8);
                        System.arraycopy(rn, 0, seed, i * 8, rn.length);
                    }

                    int extra = byteLength - ((byteLength / 8) * 8);
                    if (extra != 0)
                    {
                        sleep(ms);
                        byte[] rn = baseRandom.generateSeed(extra);
                        System.arraycopy(rn, 0, seed, seed.length - rn.length, rn.length);
                    }

                    entropy.set(seed);
                    seedAvailable.set(true);
                }
            }
        }
    }

    private static class AtomicBoolean
    {
        private volatile boolean value;

        AtomicBoolean(boolean value)
        {
            this.value = value;
        }

        public synchronized void set(boolean value)
        {
            this.value = value;
        }

        public synchronized boolean getAndSet(boolean value)
        {
            boolean tmp = this.value;

            this.value = value;

            return tmp;
        }
    }

    private static class AtomicInteger
    {
        private volatile int value;

        AtomicInteger(int value)
        {
            this.value = value;
        }

        public synchronized void set(int value)
        {
            this.value = value;
        }

        public synchronized int getAndSet(int value)
        {
            int tmp = this.value;

            this.value = value;

            return tmp;
        }

        public synchronized int getAndIncrement()
        {
            int tmp = this.value;

            this.value++;

            return tmp;
        }
    }

    private static class AtomicReference
    {
        private volatile Object value;

        public synchronized void set(Object value)
        {
            this.value = value;
        }

        public synchronized Object getAndSet(Object value)
        {
            Object tmp = this.value;

            this.value = value;

            return tmp;
        }
    }
}
