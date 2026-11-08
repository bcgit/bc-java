package org.bouncycastle.crypto.test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AsconAEAD128;
import org.bouncycastle.crypto.engines.DSTU7624Engine;
import org.bouncycastle.crypto.engines.ElephantEngine;
import org.bouncycastle.crypto.engines.GiftCofbEngine;
import org.bouncycastle.crypto.engines.Grain128AEADEngine;
import org.bouncycastle.crypto.engines.ISAPEngine;
import org.bouncycastle.crypto.engines.PhotonBeetleEngine;
import org.bouncycastle.crypto.engines.RomulusEngine;
import org.bouncycastle.crypto.engines.SparkleEngine;
import org.bouncycastle.crypto.engines.XoodyakEngine;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.modes.EAXBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.KGCMBlockCipher;
import org.bouncycastle.crypto.modes.OCBBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.test.SimpleTest;

/**
 * After a decryption fails its tag check, getMac() must not return the tag the cipher computed for the rejected
 * input: that is the valid tag for the attacker's ciphertext and associated data, so a caller that logs or returns
 * getMac() after the InvalidCipherTextException would hand out a forgery.
 */
public class AEADFailedDecryptionMacTest
    extends SimpleTest
{
    private static final SecureRandom random = new SecureRandom();

    private interface Factory
    {
        AEADCipher create();
    }

    public String getName()
    {
        return "AEADFailedDecryptionMac";
    }

    public void performTest()
        throws Exception
    {
        check("GCM", 16, 12, new Factory()
        {
            public AEADCipher create()
            {
                return GCMBlockCipher.newInstance(AESEngine.newInstance());
            }
        });
        check("EAX", 16, 12, new Factory()
        {
            public AEADCipher create()
            {
                return new EAXBlockCipher(AESEngine.newInstance());
            }
        });
        check("OCB", 16, 12, new Factory()
        {
            public AEADCipher create()
            {
                return new OCBBlockCipher(AESEngine.newInstance(), AESEngine.newInstance());
            }
        });
        check("KGCM", 16, 16, new Factory()
        {
            public AEADCipher create()
            {
                return new KGCMBlockCipher(new DSTU7624Engine(128));
            }
        });
        check("ChaCha20Poly1305", 32, 12, new Factory()
        {
            public AEADCipher create()
            {
                return new ChaCha20Poly1305();
            }
        });
        check("AsconAEAD128", 16, 16, new Factory()
        {
            public AEADCipher create()
            {
                return new AsconAEAD128();
            }
        });
        check("Elephant", 16, 12, new Factory()
        {
            public AEADCipher create()
            {
                return new ElephantEngine(ElephantEngine.ElephantParameters.elephant160);
            }
        });
        check("GIFT-COFB", 16, 16, new Factory()
        {
            public AEADCipher create()
            {
                return new GiftCofbEngine();
            }
        });
        check("Grain-128AEAD", 16, 12, new Factory()
        {
            public AEADCipher create()
            {
                return new Grain128AEADEngine();
            }
        });
        check("ISAP", 16, 16, new Factory()
        {
            public AEADCipher create()
            {
                return new ISAPEngine(ISAPEngine.IsapType.ISAP_A_128A);
            }
        });
        check("PhotonBeetle", 16, 16, new Factory()
        {
            public AEADCipher create()
            {
                return new PhotonBeetleEngine(PhotonBeetleEngine.PhotonBeetleParameters.pb32);
            }
        });
        check("Romulus-N", 16, 16, new Factory()
        {
            public AEADCipher create()
            {
                return new RomulusEngine(RomulusEngine.RomulusParameters.RomulusN);
            }
        });
        check("Romulus-T", 16, 16, new Factory()
        {
            public AEADCipher create()
            {
                return new RomulusEngine(RomulusEngine.RomulusParameters.RomulusT);
            }
        });
        check("Sparkle", 16, 16, new Factory()
        {
            public AEADCipher create()
            {
                return new SparkleEngine(SparkleEngine.SparkleParameters.SCHWAEMM128_128);
            }
        });
        check("Xoodyak", 16, 16, new Factory()
        {
            public AEADCipher create()
            {
                return new XoodyakEngine();
            }
        });
    }

    private void check(String name, int keyLen, int nonceLen, Factory factory)
        throws Exception
    {
        byte[] key = randomBytes(keyLen), nonce = randomBytes(nonceLen), aad = randomBytes(8);

        // the tag length: the output of encrypting an empty message
        int macLen = 16;
        AEADCipher sizer = factory.create();
        try
        {
            sizer.init(true, new AEADParameters(new KeyParameter(key), 128, nonce, aad));
        }
        catch (IllegalArgumentException e)
        {
            macLen = 8;
            sizer = factory.create();
            sizer.init(true, new AEADParameters(new KeyParameter(key), 64, nonce, aad));
        }
        macLen = crypt(sizer, new byte[0]).length;

        AEADParameters parameters = new AEADParameters(new KeyParameter(key), macLen * 8, nonce, aad);
        byte[] forged = randomBytes(32 + macLen);

        AEADCipher decryptor = factory.create();
        decryptor.init(false, parameters);
        try
        {
            crypt(decryptor, forged);
            fail(name + ": random tag accepted");
        }
        catch (InvalidCipherTextException e)
        {
            // expected
        }

        byte[] mac = decryptor.getMac();
        if (mac == null)
        {
            return;
        }
        isEquals(name + ": getMac() length", macLen, mac.length);

        // put what getMac() returned in place of the tag: the result must still be rejected
        System.arraycopy(mac, 0, forged, forged.length - macLen, macLen);
        AEADCipher check = factory.create();
        check.init(false, parameters);
        try
        {
            crypt(check, forged);
            fail(name + ": getMac() after a failed decryption returned a valid tag for the rejected input");
        }
        catch (InvalidCipherTextException e)
        {
            // expected
        }
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
        runTest(new AEADFailedDecryptionMacTest());
    }
}
