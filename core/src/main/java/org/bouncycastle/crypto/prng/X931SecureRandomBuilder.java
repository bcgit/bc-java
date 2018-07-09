package org.bouncycastle.crypto.prng;

import java.security.SecureRandom;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public class X931SecureRandomBuilder
{
    private SecureRandom random;          // JDK 1.1 complains on final.
    private EntropySourceProvider entropySourceProvider;

    private byte[] dateTimeVector;

    /**
     * Basic constructor, creates a builder using an EntropySourceProvider based on the default SecureRandom with
     * predictionResistant set to false.
     * <p>
     * Any SecureRandom created from a builder constructed like this will make use of input passed to SecureRandom.setSeed() if
     * the default SecureRandom does for its generateSeed() call.
     * </p>
     */
    public X931SecureRandomBuilder()
    {
        this(CryptoServicesRegistrar.getSecureRandom(), false);
    }

    /**
     * Construct a builder with an EntropySourceProvider based on the passed in SecureRandom and the passed in value
     * for prediction resistance.
     * <p>
     * Any SecureRandom created from a builder constructed like this will make use of input passed to SecureRandom.setSeed() if
     * the passed in SecureRandom does for its generateSeed() call.
     * </p>
     * @param entropySource
     * @param predictionResistant
     */
    public X931SecureRandomBuilder(SecureRandom entropySource, boolean predictionResistant)
    {
        this.random = entropySource;
        this.entropySourceProvider = new BasicEntropySourceProvider(random, predictionResistant);
    }

    /**
     * Create a builder which makes creates the SecureRandom objects from a specified entropy source provider.
     * <p>
     * <b>Note:</b> If this constructor is used any calls to setSeed() in the resulting SecureRandom will be ignored.
     * </p>
     * @param entropySourceProvider a provider of EntropySource objects.
     */
    public X931SecureRandomBuilder(EntropySourceProvider entropySourceProvider)
    {
        this.random = null;
        this.entropySourceProvider = entropySourceProvider;
    }

    public X931SecureRandomBuilder setDateTimeVector(byte[] dateTimeVector)
    {
        this.dateTimeVector = Arrays.clone(dateTimeVector);

        return this;
    }

    /**
     * Construct a X9.31 secure random generator using the passed in engine and key. If predictionResistant is true the
     * generator will be reseeded on each request.
     *
     * @param engine a block cipher to use as the operator.
     * @param key the block cipher key to initialise engine with.
     * @param predictionResistant true if engine to be reseeded on each use, false otherwise.
     * @return a SecureRandom.
     */
    public X931SecureRandom build(BlockCipher engine, KeyParameter key, boolean predictionResistant)
    {
        if (dateTimeVector == null)
        {
            dateTimeVector = new byte[engine.getBlockSize()];
            Pack.longToBigEndian(System.currentTimeMillis(), dateTimeVector, 0);
        }

        engine.init(true, key);

        return new X931SecureRandom(random, new X931RNG(engine, dateTimeVector, entropySourceProvider.get(engine.getBlockSize() * 8)), predictionResistant);
    }
}
