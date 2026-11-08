package org.bouncycastle.crypto.test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DSTU7624Engine;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.modes.EAXBlockCipher;
import org.bouncycastle.crypto.modes.KCCMBlockCipher;
import org.bouncycastle.crypto.modes.KGCMBlockCipher;
import org.bouncycastle.crypto.modes.OCBBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Once an encryption has used a key and nonce, a second message on the same instance without a new init would be
 * encrypted under the same nonce (for the CTR based modes, the same keystream). CCM, KCCM, KGCM, EAX and OCB refuse
 * that, as GCMBlockCipher and ChaCha20Poly1305 already did; decryption stays reusable.
 */
public class AEADEncryptionReuseTest
    extends SimpleTest
{
    private static final SecureRandom random = new SecureRandom();

    private interface Factory
    {
        AEADCipher create();
    }

    public String getName()
    {
        return "AEADEncryptionReuse";
    }

    public void performTest()
        throws Exception
    {
        Factory ccm = new Factory()
        {
            public AEADCipher create()
            {
                return CCMBlockCipher.newInstance(AESEngine.newInstance());
            }
        };
        Factory kccm = new Factory()
        {
            public AEADCipher create()
            {
                return new KCCMBlockCipher(new DSTU7624Engine(128));
            }
        };
        Factory kgcm = new Factory()
        {
            public AEADCipher create()
            {
                return new KGCMBlockCipher(new DSTU7624Engine(128));
            }
        };
        Factory eax = new Factory()
        {
            public AEADCipher create()
            {
                return new EAXBlockCipher(AESEngine.newInstance());
            }
        };
        Factory ocb = new Factory()
        {
            public AEADCipher create()
            {
                return new OCBBlockCipher(AESEngine.newInstance(), AESEngine.newInstance());
            }
        };

        checkAll("CCM", 12, false, ccm);
        checkAll("KCCM", 16, false, kccm);
        checkAll("KGCM", 16, false, kgcm);
        checkAll("EAX", 12, true, eax);
        checkAll("OCB", 12, true, ocb);

        // CCM processPacket is refused the same way
        CCMBlockCipher packet = (CCMBlockCipher)CCMBlockCipher.newInstance(AESEngine.newInstance());
        packet.init(true, new AEADParameters(new KeyParameter(randomBytes(16)), 128, randomBytes(12)));
        packet.processPacket(randomBytes(32), 0, 32);
        try
        {
            packet.processPacket(randomBytes(32), 0, 32);
            fail("CCM: second processPacket not refused");
        }
        catch (IllegalStateException e)
        {
            isEquals("CCM cipher cannot be reused for encryption", e.getMessage());
        }
    }

    private void checkAll(String name, int nonceLen, boolean streaming, Factory factory)
        throws Exception
    {
        byte[] key = randomBytes(16);

        // a second encryption without init is refused, before and after reset()
        AEADCipher cipher = factory.create();
        cipher.init(true, parameters(key, randomBytes(nonceLen)));
        crypt(cipher, randomBytes(32));
        try
        {
            crypt(cipher, randomBytes(32));
            fail(name + ": second encryption without init not refused");
        }
        catch (IllegalStateException e)
        {
            isEquals(name + ": message", name + " cipher cannot be reused for encryption", e.getMessage());
        }
        cipher.reset();
        try
        {
            crypt(cipher, randomBytes(32));
            fail(name + ": second encryption after reset() not refused");
        }
        catch (IllegalStateException e)
        {
            // expected
        }

        // init with a new nonce encrypts again, and the result decrypts
        byte[] nonce = randomBytes(nonceLen), message = randomBytes(32);
        cipher.init(true, parameters(key, nonce));
        byte[] ciphertext = crypt(cipher, message);

        // decryption stays reusable
        AEADCipher decryptor = factory.create();
        decryptor.init(false, parameters(key, nonce));
        isTrue(name + ": decrypt", Arrays.areEqual(message, crypt(decryptor, ciphertext)));
        isTrue(name + ": decrypt again", Arrays.areEqual(message, crypt(decryptor, ciphertext)));

        // reset() before any message data still allows encryption
        AEADCipher fresh = factory.create();
        fresh.init(true, parameters(key, randomBytes(nonceLen)));
        fresh.reset();
        crypt(fresh, randomBytes(32));

        if (streaming)
        {
            // a partial message has already produced ciphertext under the nonce: reset() does not free it
            AEADCipher partial = factory.create();
            partial.init(true, parameters(key, randomBytes(nonceLen)));
            partial.processBytes(randomBytes(48), 0, 48, new byte[64], 0);
            partial.reset();
            try
            {
                crypt(partial, randomBytes(32));
                fail(name + ": encryption after reset() of a partial message not refused");
            }
            catch (IllegalStateException e)
            {
                // expected
            }
        }
    }

    private static AEADParameters parameters(byte[] key, byte[] nonce)
    {
        // KGCM refuses a message with neither associated text nor data, so always carry some
        return new AEADParameters(new KeyParameter(key), 128, nonce, new byte[]{ 1, 2, 3 });
    }

    private static byte[] crypt(AEADCipher cipher, byte[] input)
        throws InvalidCipherTextException
    {
        byte[] output = new byte[cipher.getOutputSize(input.length)];
        int len = cipher.processBytes(input, 0, input.length, output, 0);
        len += cipher.doFinal(output, len);
        byte[] result = new byte[len];
        System.arraycopy(output, 0, result, 0, len);
        return result;
    }

    private static byte[] randomBytes(int length)
    {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }

    public static void main(String[] args)
    {
        runTest(new AEADEncryptionReuseTest());
    }
}
