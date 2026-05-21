package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.engines.XChaCha20Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * XChaCha20 stream cipher tests using the test vectors from
 * draft-irtf-cfrg-xchacha-03.
 */
public class XChaCha20Test
    extends SimpleTest
{
    public String getName()
    {
        return "XChaCha20";
    }

    public void performTest()
        throws Exception
    {
        testKeystreamSection22();
        testRoundTrip();
        testNonceLength();
    }

    /**
     * draft-irtf-cfrg-xchacha-03 sec. 2.2.1 example: encrypting an all-zero
     * plaintext with the listed key + nonce yields the published keystream
     * starting at block counter 0.
     */
    private void testKeystreamSection22()
    {
        byte[] key = Hex.decode("808182838485868788898a8b8c8d8e8f"
            + "909192939495969798999a9b9c9d9e9f");
        byte[] nonce = Hex.decode("404142434445464748494a4b4c4d4e4f"
            + "5051525354555658");
        byte[] expectedKeystream = Hex.decode(
            "1131ce9a2a20ae0d67c8935c7789fa1025c9e5bb720fb96f11354fb97af0bd9a"
                + "adec0863ba60cac8582c48f86cdfc48edd46a48642c5de62ccf11c7b21bf337d");

        XChaCha20Engine engine = new XChaCha20Engine();
        engine.init(true, new ParametersWithIV(new KeyParameter(key), nonce));

        byte[] zeros = new byte[expectedKeystream.length];
        byte[] keystream = new byte[expectedKeystream.length];
        engine.processBytes(zeros, 0, zeros.length, keystream, 0);

        if (!Arrays.areEqual(expectedKeystream, keystream))
        {
            fail("XChaCha20 keystream mismatch", Hex.toHexString(expectedKeystream), Hex.toHexString(keystream));
        }
    }

    private void testRoundTrip()
    {
        byte[] key = Hex.decode("0001020304050607080910111213141516171819202122232425262728293031");
        byte[] nonce = Hex.decode("000102030405060708090a0b0c0d0e0f1011121314151617");

        XChaCha20Engine enc = new XChaCha20Engine();
        enc.init(true, new ParametersWithIV(new KeyParameter(key), nonce));

        byte[] plain = new byte[1024];
        for (int i = 0; i < plain.length; ++i)
        {
            plain[i] = (byte)i;
        }
        byte[] cipher = new byte[plain.length];
        enc.processBytes(plain, 0, plain.length, cipher, 0);

        XChaCha20Engine dec = new XChaCha20Engine();
        dec.init(false, new ParametersWithIV(new KeyParameter(key), nonce));
        byte[] recovered = new byte[plain.length];
        dec.processBytes(cipher, 0, cipher.length, recovered, 0);

        if (!Arrays.areEqual(plain, recovered))
        {
            fail("XChaCha20 round-trip failed");
        }
        if (Arrays.areEqual(plain, cipher))
        {
            fail("XChaCha20 produced no ciphertext (input == output)");
        }
    }

    private void testNonceLength()
    {
        byte[] key = new byte[32];
        XChaCha20Engine engine = new XChaCha20Engine();
        try
        {
            engine.init(true, new ParametersWithIV(new KeyParameter(key), new byte[8]));
            fail("XChaCha20 accepted 64 bit nonce");
        }
        catch (IllegalArgumentException expected)
        {
        }

        try
        {
            engine.init(true, new ParametersWithIV(new KeyParameter(key), new byte[12]));
            fail("XChaCha20 accepted 96 bit nonce");
        }
        catch (IllegalArgumentException expected)
        {
        }
    }

    public static void main(String[] args)
    {
        runTest(new XChaCha20Test());
    }
}
