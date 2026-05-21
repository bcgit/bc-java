package org.bouncycastle.pqc.crypto.faest;

import java.security.SecureRandom;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Known-answer + cross-check tests for {@link FaestAES} and {@link Owf}.
 * <p>
 * AES-128/192/256 vectors come from {@code faest-ref/tests/aes.cpp}; they're
 * the same NIST FIPS-197 vectors plus a fixed key/plaintext combination.
 * Rijndael-192/256 vectors come from the upstream test file too.
 * <p>
 * After the KAT vectors, AES-128/192/256 are also cross-checked against BC's
 * {@link AESEngine} on random inputs to gain extra confidence beyond a single
 * vector per key size.
 */
public class FaestAESTest
    extends SimpleTest
{
    public String getName()
    {
        return "FaestAES";
    }

    public void performTest()
        throws Exception
    {
        aes128_kat();
        aes192_kat();
        aes256_kat();
        rijndael192_kat();
        rijndael256_kat();
        aes_cross_check_against_bc();
        owf_round_trip();
    }

    private void aes128_kat()
    {
        byte[] key = Hex.decode("000102030405060708090a0b0c0d0e0f");
        byte[] in  = Hex.decode("00112233445566778899aabbccddeeff");
        byte[] expected = Hex.decode("69c4e0d86a7b0430d8cdb78070b4c55a");
        byte[] out = new byte[16];
        FaestAES.aes128EncryptBlock(key, 0, in, 0, out, 0);
        isTrue("AES-128 KAT", Arrays.areEqual(expected, out));
    }

    private void aes192_kat()
    {
        byte[] key = Hex.decode("000102030405060708090a0b0c0d0e0f1011121314151617");
        byte[] in  = Hex.decode("00112233445566778899aabbccddeeff");
        byte[] expected = Hex.decode("dda97ca4864cdfe06eaf70a0ec0d7191");
        byte[] out = new byte[16];
        FaestAES.aes192EncryptBlock(key, 0, in, 0, out, 0);
        isTrue("AES-192 KAT", Arrays.areEqual(expected, out));
    }

    private void aes256_kat()
    {
        byte[] key = Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] in  = Hex.decode("00112233445566778899aabbccddeeff");
        byte[] expected = Hex.decode("8ea2b7ca516745bfeafc49904b496089");
        byte[] out = new byte[16];
        FaestAES.aes256EncryptBlock(key, 0, in, 0, out, 0);
        isTrue("AES-256 KAT", Arrays.areEqual(expected, out));
    }

    private void rijndael192_kat()
    {
        // faest-ref tests/aes.cpp:96 — key starts with 0x80 then 23 zero bytes,
        // plaintext is the all-zero 24-byte block.
        byte[] key = new byte[24];
        key[0] = (byte)0x80;
        byte[] in = new byte[24];
        byte[] expected = Hex.decode(
            "564d36fdeb8bf7e275f010b2f5ee69cfeae67ea0e37e3209");
        byte[] out = new byte[24];
        FaestAES.rijndael192EncryptBlock(key, 0, in, 0, out, 0);
        isTrue("Rijndael-192 KAT", Arrays.areEqual(expected, out));
    }

    private void rijndael256_kat()
    {
        byte[] key = new byte[32];
        key[0] = (byte)0x80;
        byte[] in = new byte[32];
        byte[] expected = Hex.decode(
            "e62abce069837b65309be4eda2c0e149fe56c07b7082d3287f592c4a4927a277");
        byte[] out = new byte[32];
        FaestAES.rijndael256EncryptBlock(key, 0, in, 0, out, 0);
        isTrue("Rijndael-256 KAT", Arrays.areEqual(expected, out));
    }

    /**
     * Cross-check FaestAES (computed-S-box, constant-time) against BC's
     * AESEngine (table-based) on random keys / plaintexts. Useful as a
     * larger-coverage second line of defence beyond the single KAT.
     */
    private void aes_cross_check_against_bc()
    {
        SecureRandom rng = fixedSeed("aes-cross");
        for (int[] sizes : new int[][]{ {16, 16}, {24, 16}, {32, 16} })
        {
            int keyLen = sizes[0];
            int blockLen = sizes[1];
            for (int trial = 0; trial < 32; trial++)
            {
                byte[] key = new byte[keyLen]; rng.nextBytes(key);
                byte[] in  = new byte[blockLen]; rng.nextBytes(in);

                byte[] viaFaest = new byte[blockLen];
                byte[] viaBC = new byte[blockLen];

                switch (keyLen)
                {
                case 16: FaestAES.aes128EncryptBlock(key, 0, in, 0, viaFaest, 0); break;
                case 24: FaestAES.aes192EncryptBlock(key, 0, in, 0, viaFaest, 0); break;
                case 32: FaestAES.aes256EncryptBlock(key, 0, in, 0, viaFaest, 0); break;
                }

                AESEngine bc = new AESEngine();
                bc.init(true, new KeyParameter(key));
                bc.processBlock(in, 0, viaBC, 0);

                isTrue("FaestAES key=" + keyLen + " trial=" + trial,
                    Arrays.areEqual(viaFaest, viaBC));
            }
        }
    }

    /**
     * OWFs must agree with a direct AESEngine for the FAEST mode (which is just
     * keyed AES), and with a hand-rolled EM construction (encrypt under input
     * as key, XOR key) for the EM-128 mode. EM-192/256 use Rijndael which BC
     * doesn't expose, so we don't double-check those here &mdash; they're
     * exercised by the KAT vectors above and the end-to-end FAEST KAT later.
     */
    private void owf_round_trip()
    {
        SecureRandom rng = fixedSeed("owf");

        // OWF-128: matches direct AES-128 of (key, input).
        {
            byte[] key = new byte[16]; rng.nextBytes(key);
            byte[] in  = new byte[16]; rng.nextBytes(in);
            byte[] viaOwf = new byte[16];
            byte[] viaDirect = new byte[16];
            Owf.owf128(key, 0, in, 0, viaOwf, 0);
            AESEngine bc = new AESEngine();
            bc.init(true, new KeyParameter(key));
            bc.processBlock(in, 0, viaDirect, 0);
            isTrue("owf128 == AES-128", Arrays.areEqual(viaOwf, viaDirect));
        }

        // OWF-EM-128: AES-128 keyed by `input`, encrypting `key`, then XOR `key`.
        {
            byte[] key = new byte[16]; rng.nextBytes(key);
            byte[] in  = new byte[16]; rng.nextBytes(in);
            byte[] viaOwf = new byte[16];
            byte[] viaDirect = new byte[16];
            Owf.owfEm128(key, 0, in, 0, viaOwf, 0);
            AESEngine bc = new AESEngine();
            bc.init(true, new KeyParameter(in));
            bc.processBlock(key, 0, viaDirect, 0);
            for (int i = 0; i < 16; i++)
            {
                viaDirect[i] = (byte)(viaDirect[i] ^ key[i]);
            }
            isTrue("owfEm128 == AES-128 EM", Arrays.areEqual(viaOwf, viaDirect));
        }
    }

    // ----- helpers -----

    private static SecureRandom fixedSeed(final String label)
    {
        return new SecureRandom()
        {
            private long state = seedFromLabel(label);

            @Override
            public void nextBytes(byte[] bytes)
            {
                for (int i = 0; i < bytes.length; i++)
                {
                    state ^= state << 13;
                    state ^= state >>> 7;
                    state ^= state << 17;
                    bytes[i] = (byte)state;
                }
            }
        };
    }

    private static long seedFromLabel(String label)
    {
        long h = 0xcbf29ce484222325L;
        for (int i = 0; i < label.length(); i++)
        {
            h ^= label.charAt(i);
            h *= 0x100000001b3L;
        }
        return h == 0L ? 1L : h;
    }

    public static void main(String[] args)
    {
        runTest(new FaestAESTest());
    }
}
