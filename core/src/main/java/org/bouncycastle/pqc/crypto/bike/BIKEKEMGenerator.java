package org.bouncycastle.pqc.crypto.bike;

import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.security.auth.DestroyFailedException;

import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Arrays;

public class BIKEKEMGenerator
    implements EncapsulatedSecretGenerator
{

    private final SecureRandom sr;

    public BIKEKEMGenerator(SecureRandom random)
    {
        this.sr = random;
    }

    @Override
    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey)
    {
        BIKEPublicKeyParameters key = (BIKEPublicKeyParameters)recipientKey;
        BIKEEngine engine = key.getParameters().getEngine();

        byte[] K = new byte[key.getParameters().getLByte()];
        byte[] c0 = new byte[key.getParameters().getRByte()];
        byte[] c1 = new byte[key.getParameters().getLByte()];
        byte[] h = key.publicKey;

        engine.encaps(c0, c1, K, h, this.sr);

        byte[] cipherText = Arrays.concatenate(c0, c1);

        return new SecretWithEncapsulationImpl(Arrays.copyOfRange(K, 0, key.getParameters().getSessionKeySize() / 8), cipherText);
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
