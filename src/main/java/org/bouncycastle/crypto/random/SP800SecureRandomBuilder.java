package org.bouncycastle.crypto.random;

import java.security.SecureRandom;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.prng.CTRSP800DRBG;
import org.bouncycastle.crypto.prng.SP80090DRBG;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.crypto.prng.HashSP800DRBG;

public class SP800SecureRandomBuilder
{
    private byte[] nonce;
    private byte[] personalizationString;
    private SecureRandom random;
    private boolean predictionResistantSource;
    private int seedLength;
    private int securityStrength;

    public SP800SecureRandomBuilder setNonce(byte[] nonce)
    {
        this.nonce = nonce;

        return this;
    }

    public SP800SecureRandomBuilder setPersonalizationString(byte[] personalizationString)
    {
        this.personalizationString = personalizationString;

        return this;
    }

    public SP800SecureRandomBuilder setEntropySource(SecureRandom entropySource, boolean predictionResistant)
    {
        this.random = entropySource;
        this.predictionResistantSource = predictionResistant;

        return this;
    }

    public SP800SecureRandomBuilder setSeedLength(int seedLength)
    {
        this.seedLength = seedLength;

        return this;
    }

    public SP800SecureRandomBuilder setSecurityStrength(int securityStrength)
    {
        this.securityStrength = securityStrength;

        return this;
    }

    public SP800SecureRandom build(Digest digest, boolean predictionResistant)
    {
        checkSettings();

        return new SP800SecureRandom(random, predictionResistantSource, new HashDRBGProvider(digest, seedLength, nonce, personalizationString, securityStrength), predictionResistant);
    }

    public SP800SecureRandom build(BlockCipher cipher, int keySizeInBits, boolean predictionResistant)
    {
        checkSettings();

        return new SP800SecureRandom(random, predictionResistantSource, new CTRDRBGProvider(cipher, keySizeInBits, seedLength, nonce, personalizationString, securityStrength), predictionResistant);
    }

    private void checkSettings()
    {
        if (random == null)
        {
            random = new SecureRandom();
            predictionResistantSource = false;
        }
    }

    private static class HashDRBGProvider
        implements DRBGProvider
    {

        private final Digest digest;
        private final int seedLength;
        private final byte[] nonce;
        private final byte[] personalizationString;
        private final int securityStrength;

        public HashDRBGProvider(Digest digest, int seedLength, byte[] nonce, byte[] personalizationString, int securityStrength)
        {
            this.digest = digest;
            this.seedLength = seedLength;
            this.nonce = nonce;
            this.personalizationString = personalizationString;
            this.securityStrength = securityStrength;
        }

        public SP80090DRBG get(EntropySource entropySource)
        {
            return new HashSP800DRBG(digest, seedLength, entropySource, nonce, personalizationString, securityStrength);
        }
    }

    private static class CTRDRBGProvider
        implements DRBGProvider
    {

        private final BlockCipher blockCipher;
        private final int keySizeInBits;
        private final int seedLength;
        private final byte[] nonce;
        private final byte[] personalizationString;
        private final int securityStrength;

        public CTRDRBGProvider(BlockCipher blockCipher, int keySizeInBits, int seedLength, byte[] nonce, byte[] personalizationString, int securityStrength)
        {
            this.blockCipher = blockCipher;
            this.keySizeInBits = keySizeInBits;
            this.seedLength = seedLength;
            this.nonce = nonce;
            this.personalizationString = personalizationString;
            this.securityStrength = securityStrength;
        }

        public SP80090DRBG get(EntropySource entropySource)
        {
            return new CTRSP800DRBG(blockCipher, keySizeInBits, seedLength, entropySource, nonce, personalizationString, securityStrength);
        }
    }
}
