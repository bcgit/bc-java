package org.bouncycastle.pqc.crypto.cmce;

import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.security.auth.DestroyFailedException;

import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Arrays;

public class CMCEKEMGenerator
    implements EncapsulatedSecretGenerator
{
    // the source of randomness
    private final SecureRandom sr;

    public CMCEKEMGenerator(SecureRandom random)
    {
        this.sr = random;
    }

    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey)
    {
        CMCEPublicKeyParameters key = (CMCEPublicKeyParameters)recipientKey;
        CMCEEngine engine = key.getParameters().getEngine();
        byte[] cipher_text = new byte[engine.getCipherTextSize()];
        byte[] sessionKey = new byte[32];     // l/8  - Section 2.5.2
        engine.kem_enc(cipher_text, sessionKey, key.getPublicKey(), sr);
        return new SecretWithEncapsulationImpl(sessionKey, cipher_text);
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

        public void destroy() throws DestroyFailedException
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
