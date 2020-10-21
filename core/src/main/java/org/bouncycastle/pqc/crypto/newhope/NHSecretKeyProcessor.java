package org.bouncycastle.pqc.crypto.newhope;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.pqc.crypto.ExchangePair;
import org.bouncycastle.util.Arrays;

/**
 * A processor with associated builders for doing secret key transformation using
 * the New Hope algorithm.
 */
public class NHSecretKeyProcessor
{
    /**
     * Party U (initiator) processor builder.
     */
    public static class PartyUBuilder
    {
        private final AsymmetricCipherKeyPair aKp;
        private final NHAgreement agreement = new NHAgreement();

        private byte[] sharedInfo = null;
        private boolean used = false;

        public PartyUBuilder(SecureRandom random)
        {
            NHKeyPairGenerator kpGen = new NHKeyPairGenerator();

            kpGen.init(new KeyGenerationParameters(random, 2048));

            aKp = kpGen.generateKeyPair();

            agreement.init(aKp.getPrivate());
        }

        public PartyUBuilder withSharedInfo(byte[] sharedInfo)
        {
            this.sharedInfo = Arrays.clone(sharedInfo);

            return this;
        }

        public byte[] getPartA()
        {
            return ((NHPublicKeyParameters)aKp.getPublic()).getPubData();
        }

        public NHSecretKeyProcessor build(byte[] partB)
        {
            if (used)
            {
                throw new IllegalStateException("builder already used");
            }

            used = true;

            return new NHSecretKeyProcessor(agreement.calculateAgreement(new NHPublicKeyParameters(partB)), sharedInfo);
        }
    }

    /**
     * Party V (responder) processor builder.
     */
    public static class PartyVBuilder
    {
        protected final SecureRandom random;

        private byte[] sharedInfo = null;
        private byte[] sharedSecret = null;
        private boolean used = false;

        public PartyVBuilder(SecureRandom random)
        {
            this.random = random;
        }

        public PartyVBuilder withSharedInfo(byte[] sharedInfo)
        {
            this.sharedInfo = Arrays.clone(sharedInfo);

            return this;
        }

        public byte[] getPartB(byte[] partUContribution)
        {
            NHExchangePairGenerator exchGen = new NHExchangePairGenerator(random);

            ExchangePair bEp = exchGen.generateExchange(new NHPublicKeyParameters(partUContribution));

            sharedSecret = bEp.getSharedValue();

            return ((NHPublicKeyParameters)bEp.getPublicKey()).getPubData();
        }

        public NHSecretKeyProcessor build()
        {
            if (used)
            {
                throw new IllegalStateException("builder already used");
            }

            used = true;

            return new NHSecretKeyProcessor(sharedSecret, sharedInfo);
        }
    }

    private final Xof xof = new SHAKEDigest(256);

    private NHSecretKeyProcessor(byte[] secret, byte[] shared)
    {
        xof.update(secret, 0, secret.length);

        if (shared != null)
        {
            xof.update(shared, 0, shared.length);
        }

        Arrays.fill(secret, (byte)0);
    }

    public byte[] processKey(byte[] initialKey)
    {
        byte[] xorBytes = new byte[initialKey.length];

        xof.doFinal(xorBytes, 0, xorBytes.length);

        xor(initialKey, xorBytes);

        Arrays.fill(xorBytes, (byte)0);

        return initialKey;
    }

    private static void xor(byte[] a, byte[] b)
    {
        for (int i = 0; i != a.length; i++)
        {
            a[i] ^= b[i];
        }
    }
}
