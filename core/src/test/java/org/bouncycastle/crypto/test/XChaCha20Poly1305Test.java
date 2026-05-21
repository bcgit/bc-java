package org.bouncycastle.crypto.test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.XChaCha20Poly1305;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * XChaCha20-Poly1305 AEAD tests using the test vector from
 * draft-irtf-cfrg-xchacha-03 Appendix A.3.
 */
public class XChaCha20Poly1305Test
    extends SimpleTest
{
    private static final byte[] A3_KEY = Hex.decode(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    private static final byte[] A3_NONCE = Hex.decode(
        "404142434445464748494a4b4c4d4e4f5051525354555657");
    private static final byte[] A3_AAD = Hex.decode(
        "50515253c0c1c2c3c4c5c6c7");
    private static final byte[] A3_PLAINTEXT = Hex.decode(
        "4c616469657320616e642047656e746c"
            + "656d656e206f662074686520636c6173"
            + "73206f66202739393a20496620492063"
            + "6f756c64206f6666657220796f75206f"
            + "6e6c79206f6e652074697020666f7220"
            + "746865206675747572652c2073756e73"
            + "637265656e20776f756c642062652069"
            + "742e");
    private static final byte[] A3_CIPHERTEXT = Hex.decode(
        "bd6d179d3e83d43b9576579493c0e939"
            + "572a1700252bfaccbed2902c21396cbb"
            + "731c7f1b0b4aa6440bf3a82f4eda7e39"
            + "ae64c6708c54c216cb96b72e1213b452"
            + "2f8c9ba40db5d945b11b69b982c1bb9e"
            + "3f3fac2bc369488f76b2383565d3fff9"
            + "21f9664c97637da9768812f615c68b13"
            + "b52e");
    private static final byte[] A3_TAG = Hex.decode(
        "c0875924c1c7987947deafd8780acf49");

    public String getName()
    {
        return "XChaCha20Poly1305";
    }

    public void performTest()
        throws Exception
    {
        testAppendixA3();
        testRoundTrip();
        testTamperedTag();
        testNonceLength();
        testReuseNonceRejected();
    }

    private void testAppendixA3()
        throws InvalidCipherTextException
    {
        XChaCha20Poly1305 enc = new XChaCha20Poly1305();
        enc.init(true, new AEADParameters(new KeyParameter(A3_KEY), 128, A3_NONCE, A3_AAD));

        byte[] out = new byte[enc.getOutputSize(A3_PLAINTEXT.length)];
        int len = enc.processBytes(A3_PLAINTEXT, 0, A3_PLAINTEXT.length, out, 0);
        len += enc.doFinal(out, len);

        byte[] expected = Arrays.concatenate(A3_CIPHERTEXT, A3_TAG);
        if (len != expected.length || !Arrays.areEqual(expected, out))
        {
            fail("XChaCha20Poly1305 A.3 vector mismatch",
                Hex.toHexString(expected), Hex.toHexString(out, 0, len));
        }

        XChaCha20Poly1305 dec = new XChaCha20Poly1305();
        dec.init(false, new AEADParameters(new KeyParameter(A3_KEY), 128, A3_NONCE, A3_AAD));
        byte[] recovered = new byte[dec.getOutputSize(out.length)];
        int rlen = dec.processBytes(out, 0, out.length, recovered, 0);
        rlen += dec.doFinal(recovered, rlen);

        if (rlen != A3_PLAINTEXT.length || !Arrays.areEqual(A3_PLAINTEXT,
            Arrays.copyOf(recovered, rlen)))
        {
            fail("XChaCha20Poly1305 A.3 decrypt mismatch");
        }
    }

    private void testRoundTrip()
        throws InvalidCipherTextException
    {
        SecureRandom random = new SecureRandom();
        byte[] key = new byte[32];
        byte[] nonce = new byte[24];
        byte[] aad = new byte[33];
        byte[] plain = new byte[2048];
        random.nextBytes(key);
        random.nextBytes(nonce);
        random.nextBytes(aad);
        random.nextBytes(plain);

        XChaCha20Poly1305 enc = new XChaCha20Poly1305();
        enc.init(true, new AEADParameters(new KeyParameter(key), 128, nonce, aad));
        byte[] cipher = new byte[enc.getOutputSize(plain.length)];
        int clen = enc.processBytes(plain, 0, plain.length, cipher, 0);
        clen += enc.doFinal(cipher, clen);

        XChaCha20Poly1305 dec = new XChaCha20Poly1305();
        dec.init(false, new AEADParameters(new KeyParameter(key), 128, nonce, aad));
        byte[] out = new byte[dec.getOutputSize(clen)];
        int olen = dec.processBytes(cipher, 0, clen, out, 0);
        olen += dec.doFinal(out, olen);

        if (olen != plain.length || !Arrays.areEqual(plain, Arrays.copyOf(out, olen)))
        {
            fail("XChaCha20Poly1305 random round-trip failed");
        }
    }

    private void testTamperedTag()
    {
        XChaCha20Poly1305 enc = new XChaCha20Poly1305();
        enc.init(true, new AEADParameters(new KeyParameter(A3_KEY), 128, A3_NONCE, A3_AAD));
        byte[] out = new byte[enc.getOutputSize(A3_PLAINTEXT.length)];
        try
        {
            int len = enc.processBytes(A3_PLAINTEXT, 0, A3_PLAINTEXT.length, out, 0);
            enc.doFinal(out, len);
        }
        catch (InvalidCipherTextException e)
        {
            fail("encryption should not throw");
        }

        out[out.length - 1] ^= 0x01;

        XChaCha20Poly1305 dec = new XChaCha20Poly1305();
        dec.init(false, new AEADParameters(new KeyParameter(A3_KEY), 128, A3_NONCE, A3_AAD));
        byte[] recovered = new byte[dec.getOutputSize(out.length)];
        try
        {
            int rlen = dec.processBytes(out, 0, out.length, recovered, 0);
            dec.doFinal(recovered, rlen);
            fail("Tampered tag should fail authentication");
        }
        catch (InvalidCipherTextException expected)
        {
            if (!"mac check in XChaCha20Poly1305 failed".equals(expected.getMessage()))
            {
                fail("unexpected message: " + expected.getMessage());
            }
        }
    }

    private void testNonceLength()
    {
        XChaCha20Poly1305 cipher = new XChaCha20Poly1305();
        try
        {
            cipher.init(true, new AEADParameters(new KeyParameter(A3_KEY), 128, new byte[12]));
            fail("XChaCha20Poly1305 accepted 96 bit nonce");
        }
        catch (IllegalArgumentException expected)
        {
            if (!"Nonce must be 192 bits".equals(expected.getMessage()))
            {
                fail("unexpected message: " + expected.getMessage());
            }
        }
    }

    private void testReuseNonceRejected()
        throws InvalidCipherTextException
    {
        XChaCha20Poly1305 cipher = new XChaCha20Poly1305();
        cipher.init(true, new AEADParameters(new KeyParameter(A3_KEY), 128, A3_NONCE));
        byte[] out = new byte[cipher.getOutputSize(0)];
        cipher.doFinal(out, 0);

        try
        {
            cipher.init(true, new AEADParameters(new KeyParameter(A3_KEY), 128, A3_NONCE));
            fail("XChaCha20Poly1305 allowed nonce reuse for encryption");
        }
        catch (IllegalArgumentException expected)
        {
            if (!"cannot reuse nonce for XChaCha20Poly1305 encryption".equals(expected.getMessage()))
            {
                fail("unexpected message: " + expected.getMessage());
            }
        }
    }

    public static void main(String[] args)
    {
        runTest(new XChaCha20Poly1305Test());
    }
}
