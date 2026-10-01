package org.bouncycastle.jcajce.provider.drbg;

import java.security.DrbgParameters;
import java.security.SecureRandomParameters;
import java.security.SecureRandomSpi;

import org.bouncycastle.crypto.prng.SP800SecureRandom;

/**
 * The DEFAULT and NONCEANDIV SecureRandom SPIs for Java 9 and later, which accept
 * java.security.DrbgParameters: an Instantiation passed to SecureRandom.getInstance() creates a
 * DRBG of its own with the requested security strength, capability and personalization string,
 * NextBytes supplies additional input (and may ask for prediction resistance) on a request, and
 * Reseed does the same for a reseed. Without parameters an instance uses the same shared DRBG as
 * the DRBG SPIs do on earlier JDKs.
 */
public class ParameterisedDRBG
{
    private static final int MAX_STRENGTH = 256;

    private ParameterisedDRBG()
    {
    }

    public static class Default
        extends ParameterisedSpi
    {
        public Default()
        {
            this(null);
        }

        public Default(SecureRandomParameters params)
        {
            super(true, params);
        }
    }

    public static class NonceAndIV
        extends ParameterisedSpi
    {
        public NonceAndIV()
        {
            this(null);
        }

        public NonceAndIV(SecureRandomParameters params)
        {
            super(false, params);
        }
    }

    static class ParameterisedSpi
        extends SecureRandomSpi
    {
        private final SP800SecureRandom random;
        private final int strength;
        private final DrbgParameters.Capability capability;
        private final DrbgParameters.Instantiation parameters;

        ParameterisedSpi(boolean isDefault, SecureRandomParameters params)
        {
            byte[] personalizationString = null;

            if (params == null)
            {
                this.random = isDefault ? DRBG.getDefaultRandom() : DRBG.getNonceAndIVRandom();
                this.strength = MAX_STRENGTH;
                this.capability = isDefault ? DrbgParameters.Capability.PR_AND_RESEED : DrbgParameters.Capability.RESEED_ONLY;
            }
            else if (params instanceof DrbgParameters.Instantiation)
            {
                DrbgParameters.Instantiation instantiation = (DrbgParameters.Instantiation)params;

                personalizationString = instantiation.getPersonalizationString();
                this.strength = getStrength(instantiation.getStrength());
                this.capability = instantiation.getCapability();
                this.random = DRBG.createBaseRandom(isDefault, capability.supportsPredictionResistance(), strength,
                    personalizationString);
            }
            else
            {
                throw new IllegalArgumentException("unsupported SecureRandomParameters: " + params.getClass().getName());
            }

            // a generated personalization string carries entropy, so only a caller's own is reported back.
            this.parameters = DrbgParameters.instantiation(strength, capability, personalizationString);
        }

        protected void engineSetSeed(byte[] bytes)
        {
            random.setSeed(bytes);
        }

        protected void engineNextBytes(byte[] bytes)
        {
            random.nextBytes(bytes);
        }

        protected void engineNextBytes(byte[] bytes, SecureRandomParameters params)
        {
            if (params == null)
            {
                engineNextBytes(bytes);
                return;
            }
            if (!(params instanceof DrbgParameters.NextBytes))
            {
                throw new IllegalArgumentException("unsupported SecureRandomParameters: " + params.getClass().getName());
            }

            DrbgParameters.NextBytes nextBytes = (DrbgParameters.NextBytes)params;

            if (nextBytes.getStrength() > strength)
            {
                throw new IllegalArgumentException("requested strength " + nextBytes.getStrength()
                    + " exceeds DRBG strength of " + strength);
            }
            checkPredictionResistance(nextBytes.getPredictionResistance());

            random.nextBytes(bytes, nextBytes.getAdditionalInput());
        }

        protected byte[] engineGenerateSeed(int numBytes)
        {
            return random.generateSeed(numBytes);
        }

        protected void engineReseed(SecureRandomParameters params)
        {
            if (!capability.supportsReseeding())
            {
                throw new UnsupportedOperationException("DRBG does not support reseeding");
            }
            if (params == null)
            {
                random.reseed((byte[])null);
                return;
            }
            if (!(params instanceof DrbgParameters.Reseed))
            {
                throw new IllegalArgumentException("unsupported SecureRandomParameters: " + params.getClass().getName());
            }

            DrbgParameters.Reseed reseed = (DrbgParameters.Reseed)params;

            checkPredictionResistance(reseed.getPredictionResistance());

            random.reseed(reseed.getAdditionalInput());
        }

        protected SecureRandomParameters engineGetParameters()
        {
            return parameters;
        }

        private void checkPredictionResistance(boolean predictionResistance)
        {
            if (predictionResistance && !capability.supportsPredictionResistance())
            {
                throw new IllegalArgumentException("prediction resistance not available");
            }
        }
    }

    // SP 800-57 strengths; -1 asks for the default, which is the DRBG's maximum.
    private static int getStrength(int requested)
    {
        if (requested < 0)
        {
            return MAX_STRENGTH;
        }
        if (requested > MAX_STRENGTH)
        {
            throw new IllegalArgumentException("requested strength " + requested + " exceeds maximum of " + MAX_STRENGTH);
        }
        if (requested <= 112)
        {
            return 112;
        }
        if (requested <= 128)
        {
            return 128;
        }
        if (requested <= 192)
        {
            return 192;
        }
        return MAX_STRENGTH;
    }
}
