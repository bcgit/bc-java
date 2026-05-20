package org.bouncycastle.jce.provider.test;

import java.security.AlgorithmParameters;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * JCE-side smoke test for the BC XChaCha20 stream cipher and
 * XChaCha20-Poly1305 AEAD registrations. Round-trips through
 * {@code Cipher.getInstance("XChaCha20", "BC")} and
 * {@code Cipher.getInstance("XChaCha20-Poly1305", "BC")} and verifies the
 * draft-irtf-cfrg-xchacha-03 Appendix A.3 AEAD test vector through the JCE
 * surface.
 */
public class XChaCha20Poly1305Test
    extends SimpleTest
{
    private static final byte[] A3_KEY = Hex.decode(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    private static final byte[] A3_NONCE = Hex.decode(
        "404142434445464748494a4b4c4d4e4f5051525354555657");
    private static final byte[] A3_PLAINTEXT = Hex.decode(
        "4c616469657320616e642047656e746c"
            + "656d656e206f662074686520636c6173"
            + "73206f66202739393a20496620492063"
            + "6f756c64206f6666657220796f75206f"
            + "6e6c79206f6e652074697020666f7220"
            + "746865206675747572652c2073756e73"
            + "637265656e20776f756c642062652069"
            + "742e");
    private static final byte[] A3_AAD = Hex.decode(
        "50515253c0c1c2c3c4c5c6c7");
    private static final byte[] A3_CIPHERTEXT_AND_TAG = Hex.decode(
        "bd6d179d3e83d43b9576579493c0e939"
            + "572a1700252bfaccbed2902c21396cbb"
            + "731c7f1b0b4aa6440bf3a82f4eda7e39"
            + "ae64c6708c54c216cb96b72e1213b452"
            + "2f8c9ba40db5d945b11b69b982c1bb9e"
            + "3f3fac2bc369488f76b2383565d3fff9"
            + "21f9664c97637da9768812f615c68b13"
            + "b52e"
            + "c0875924c1c7987947deafd8780acf49");

    public String getName()
    {
        return "XChaCha20Poly1305";
    }

    public void performTest()
        throws Exception
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        testStreamRoundTrip();
        testAeadAppendixA3();
        testAeadRoundTripAndTamper();
    }

    private void testStreamRoundTrip()
        throws Exception
    {
        KeyGenerator kg = KeyGenerator.getInstance("XChaCha20", "BC");
        if (kg.generateKey().getEncoded().length != 32)
        {
            fail("XChaCha20 KeyGenerator produced wrong key size");
        }

        Cipher enc = Cipher.getInstance("XChaCha20", "BC");
        Cipher dec = Cipher.getInstance("XChaCha20", "BC");

        SecretKey key = new SecretKeySpec(A3_KEY, "XChaCha20");
        IvParameterSpec iv = new IvParameterSpec(A3_NONCE);

        byte[] msg = Strings.toByteArray("the quick brown fox jumps over the lazy dog");

        enc.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipher = enc.doFinal(msg);

        dec.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] recovered = dec.doFinal(cipher);

        if (!areEqual(msg, recovered))
        {
            fail("XChaCha20 stream-cipher JCE round-trip failed");
        }
    }

    private void testAeadAppendixA3()
        throws Exception
    {
        Cipher enc = Cipher.getInstance("XChaCha20-Poly1305", "BC");
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(A3_KEY, "XChaCha20"),
            new IvParameterSpec(A3_NONCE));
        enc.updateAAD(A3_AAD);
        byte[] out = enc.doFinal(A3_PLAINTEXT);

        if (!areEqual(A3_CIPHERTEXT_AND_TAG, out))
        {
            fail("XChaCha20-Poly1305 JCE A.3 vector mismatch",
                Hex.toHexString(A3_CIPHERTEXT_AND_TAG), Hex.toHexString(out));
        }

        Cipher dec = Cipher.getInstance("XChaCha20-Poly1305", "BC");
        dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(A3_KEY, "XChaCha20"),
            new IvParameterSpec(A3_NONCE));
        dec.updateAAD(A3_AAD);
        byte[] recovered = dec.doFinal(out);

        if (!areEqual(A3_PLAINTEXT, recovered))
        {
            fail("XChaCha20-Poly1305 JCE A.3 decrypt mismatch");
        }
    }

    private void testAeadRoundTripAndTamper()
        throws Exception
    {
        KeyGenerator kg = KeyGenerator.getInstance("XChaCha20", "BC");
        SecretKey key = kg.generateKey();

        byte[] nonce = new byte[24];
        for (int i = 0; i < nonce.length; ++i)
        {
            nonce[i] = (byte)i;
        }

        Cipher enc = Cipher.getInstance("XChaCha20-Poly1305", "BC");
        enc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(nonce));
        byte[] aad = Strings.toByteArray("hello");
        enc.updateAAD(aad);
        byte[] msg = Strings.toByteArray("XChaCha20-Poly1305 round-trips through the JCE Cipher API.");
        byte[] ct = enc.doFinal(msg);

        AlgorithmParameters params = enc.getParameters();
        byte[] paramsIv = ((IvParameterSpec)params.getParameterSpec(IvParameterSpec.class)).getIV();
        if (paramsIv.length != 24 || !areEqual(nonce, paramsIv))
        {
            fail("XChaCha20-Poly1305 AlgorithmParameters did not round-trip the 24-byte IV");
        }

        Cipher dec = Cipher.getInstance("XChaCha20-Poly1305", "BC");
        dec.init(Cipher.DECRYPT_MODE, key, params);
        dec.updateAAD(aad);
        byte[] recovered = dec.doFinal(ct);
        if (!areEqual(msg, recovered))
        {
            fail("XChaCha20-Poly1305 JCE round-trip failed");
        }

        byte[] tampered = new byte[ct.length];
        System.arraycopy(ct, 0, tampered, 0, ct.length);
        tampered[tampered.length - 1] ^= 0x01;

        Cipher dec2 = Cipher.getInstance("XChaCha20-Poly1305", "BC");
        dec2.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(nonce));
        dec2.updateAAD(aad);
        try
        {
            dec2.doFinal(tampered);
            fail("Tampered ciphertext should fail authentication");
        }
        catch (Exception e)
        {
            if (e.getMessage() == null || !e.getMessage().contains("mac check in XChaCha20Poly1305 failed"))
            {
                fail("unexpected MAC failure: " + e.getMessage());
            }
        }
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());
        runTest(new XChaCha20Poly1305Test());
    }
}
