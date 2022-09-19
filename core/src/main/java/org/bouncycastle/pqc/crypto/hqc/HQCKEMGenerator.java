package org.bouncycastle.pqc.crypto.hqc;

import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.security.auth.DestroyFailedException;

import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Arrays;

public class HQCKEMGenerator
    implements EncapsulatedSecretGenerator
{
    private final SecureRandom sr;

    public HQCKEMGenerator(SecureRandom random)
    {
        this.sr = random;
    }

    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey)
    {
        HQCPublicKeyParameters key = (HQCPublicKeyParameters)recipientKey;
        HQCEngine engine = key.getParameters().getEngine();

        byte[] K = new byte[key.getParameters().getSHA512_BYTES()];
        byte[] u = new byte[key.getParameters().getN_BYTES()];
        byte[] v = new byte[key.getParameters().getN1N2_BYTES()];
        byte[] d = new byte[key.getParameters().getSHA512_BYTES()];
        byte[] pk = key.getPublicKey();
        byte[] seed = new byte[48];

        sr.nextBytes(seed);

        engine.encaps(u, v, K, d, pk, seed);

        byte[] cipherText = Arrays.concatenate(u, v);
        cipherText = Arrays.concatenate(cipherText, d);

        return new HQCKEMGenerator.SecretWithEncapsulationImpl(K, cipherText);
    }

    private class SecretWithEncapsulationImpl
        implements SecretWithEncapsulation
    {
        private final AtomicBoolean hasBeenDestroyed = new AtomicBoolean(false);

        private final byte[] sessionKey;
        private final byte[] cipher_text;

        public SecretWithEncapsulationImpl(byte[] sessionKey, byte[] cipher_text)
        {
            this.sessionKey = sessionKey;
            this.cipher_text = cipher_text;
        }

        public byte[] getSecret()
        {
            checkDestroyed();

            return Arrays.clone(sessionKey);
        }

        public byte[] getEncapsulation()
        {
            checkDestroyed();

            return Arrays.clone(cipher_text);
        }

        public void destroy()
            throws DestroyFailedException
        {
            if (!hasBeenDestroyed.getAndSet(true))
            {
                Arrays.clear(sessionKey);
                Arrays.clear(cipher_text);
            }
        }

        public boolean isDestroyed()
        {
            return hasBeenDestroyed.get();
        }

        void checkDestroyed()
        {
            if (isDestroyed())
            {
                throw new IllegalStateException("data has been destroyed");
            }
        }
    }
}
