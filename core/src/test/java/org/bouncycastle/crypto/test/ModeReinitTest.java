package org.bouncycastle.crypto.test;

import java.security.SecureRandom;
import java.util.Random;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.MultiBlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestFailedException;

/**
 * Re-initialisation of CBC and CFB with partial parameters: a key without an IV, an IV without
 * a key, or null.
 * <p>
 * CBC and CFB differ here. CBC goes back to a zero IV when re-initialised without one, and cannot
 * change direction without a key. CFB keeps the IV from its last init, and can change direction
 * without a key, as its underlying cipher is only ever used to encrypt.
 * </p>
 * Expected values come from a reference built on the raw block cipher, not from the mode under test.
 */
public class ModeReinitTest
    extends SimpleTest
{
    private static final int BLOCK_SIZE = 16;

    private Random random;

    public String getName()
    {
        return "ModeReinit";
    }

    public void performTest()
        throws Exception
    {
        long seed = new SecureRandom().nextLong();
        random = new Random(seed);

        try
        {
            referenceCheck();
            for (int i = 0; i != 10; i++)
            {
                cbcKeyOnlyReinit();
                cbcNullReinit();
                cbcIVOnlyReinit();
                cfbKeyOnlyReinit(BLOCK_SIZE);
                cfbKeyOnlyReinit(1);
                cfbNullReinit(BLOCK_SIZE);
                cfbNullReinit(1);
                cfbIVOnlyReinit(BLOCK_SIZE);
                cfbIVOnlyReinit(1);
            }
            cbcDirectionChangeRefused();
        }
        catch (TestFailedException e)
        {
            fail("failed with seed " + seed + ": " + e.getResult());
        }
        catch (RuntimeException e)
        {
            fail("failed with seed " + seed, e);
        }
    }

    /**
     * Check the references against the first block of the SP 800-38A F.2.1, F.3.13 and F.3.7
     * vectors, and that a changed key or IV changes their output.
     */
    private void referenceCheck()
    {
        byte[] key = Hex.decode("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] iv = Hex.decode("000102030405060708090a0b0c0d0e0f");
        byte[] pt = Hex.decode("6bc1bee22e409f96e93d7e117393172a");

        isTrue("reference CBC", Arrays.areEqual(Hex.decode("7649abac8119b246cee98e9b12e9197d"), refCBCEncrypt(key, iv, pt)));
        isTrue("reference CBC decrypt", Arrays.areEqual(pt, refCBCDecrypt(key, iv, Hex.decode("7649abac8119b246cee98e9b12e9197d"))));
        isTrue("reference CFB-128", Arrays.areEqual(Hex.decode("3b3fd92eb72dad20333449f8e83cfb4a"), refCFB(true, key, iv, BLOCK_SIZE, pt)));
        isTrue("reference CFB-8", Arrays.areEqual(Hex.decode("3b79424c9c0dd436bace9e0ed4586a4f"), refCFB(true, key, iv, 1, pt)));

        byte[] other = Arrays.clone(key);
        other[0] ^= 1;
        isTrue("reference CBC key", !Arrays.areEqual(refCBCEncrypt(key, iv, pt), refCBCEncrypt(other, iv, pt)));
        isTrue("reference CFB key", !Arrays.areEqual(refCFB(true, key, iv, 1, pt), refCFB(true, other, iv, 1, pt)));
        other = Arrays.clone(iv);
        other[15] ^= 1;
        isTrue("reference CBC IV", !Arrays.areEqual(refCBCEncrypt(key, iv, pt), refCBCEncrypt(key, other, pt)));
        isTrue("reference CFB IV", !Arrays.areEqual(refCFB(true, key, iv, 1, pt), refCFB(true, key, other, 1, pt)));
    }

    /**
     * A key-only re-init of CBC uses the new key with a zero IV, not the IV of the last init.
     */
    private void cbcKeyOnlyReinit()
    {
        byte[] key1 = randomBytes(16), key2 = randomBytes(16), iv = randomBytes(BLOCK_SIZE);
        byte[] pt = randomBytes(BLOCK_SIZE * (1 + random.nextInt(8)));

        for (boolean forEncryption = true; ; forEncryption = false)
        {
            byte[] in = forEncryption ? pt : refCBCEncrypt(key2, new byte[BLOCK_SIZE], pt);
            byte[] expected = forEncryption ? refCBCEncrypt(key2, new byte[BLOCK_SIZE], pt) : pt;

            BlockCipher[] ciphers = cbcCiphers();
            for (int i = 0; i != ciphers.length; i++)
            {
                BlockCipher cbc = ciphers[i];
                cbc.init(forEncryption, new ParametersWithIV(new KeyParameter(key1), iv));
                process(cbc, randomBytes(BLOCK_SIZE * 2));

                cbc.init(forEncryption, new KeyParameter(key2));
                isTrue("CBC key-only re-init " + forEncryption, Arrays.areEqual(expected, process(cbc, in)));

                // continuing with the old IV must give a different answer.
                byte[] withOldIV = forEncryption ? refCBCEncrypt(key2, iv, pt) : refCBCDecrypt(key2, iv, in);
                isTrue("CBC key-only re-init kept IV " + forEncryption, !Arrays.areEqual(withOldIV, expected));
            }

            if (!forEncryption)
            {
                break;
            }
        }
    }

    /**
     * A null re-init of CBC in the same direction keeps the key and uses a zero IV.
     */
    private void cbcNullReinit()
    {
        byte[] key = randomBytes(16), iv = randomBytes(BLOCK_SIZE);
        byte[] pt = randomBytes(BLOCK_SIZE * (1 + random.nextInt(8)));

        for (boolean forEncryption = true; ; forEncryption = false)
        {
            byte[] in = forEncryption ? pt : refCBCEncrypt(key, new byte[BLOCK_SIZE], pt);
            byte[] expected = forEncryption ? refCBCEncrypt(key, new byte[BLOCK_SIZE], pt) : pt;

            BlockCipher[] ciphers = cbcCiphers();
            for (int i = 0; i != ciphers.length; i++)
            {
                BlockCipher cbc = ciphers[i];
                cbc.init(forEncryption, new ParametersWithIV(new KeyParameter(key), iv));
                process(cbc, randomBytes(BLOCK_SIZE * 2));

                cbc.init(forEncryption, null);
                isTrue("CBC null re-init " + forEncryption, Arrays.areEqual(expected, process(cbc, in)));
            }

            if (!forEncryption)
            {
                break;
            }
        }
    }

    /**
     * An IV-only re-init of CBC keeps the key and uses the new IV, in either direction.
     */
    private void cbcIVOnlyReinit()
    {
        byte[] key = randomBytes(16), iv1 = randomBytes(BLOCK_SIZE), iv2 = randomBytes(BLOCK_SIZE);
        byte[] pt = randomBytes(BLOCK_SIZE * (1 + random.nextInt(8)));

        for (boolean forEncryption = true; ; forEncryption = false)
        {
            byte[] in = forEncryption ? pt : refCBCEncrypt(key, iv2, pt);
            byte[] expected = forEncryption ? refCBCEncrypt(key, iv2, pt) : pt;

            BlockCipher[] ciphers = cbcCiphers();
            for (int i = 0; i != ciphers.length; i++)
            {
                BlockCipher cbc = ciphers[i];
                cbc.init(forEncryption, new ParametersWithIV(new KeyParameter(key), iv1));
                process(cbc, randomBytes(BLOCK_SIZE * 2));

                cbc.init(forEncryption, new ParametersWithIV(null, iv2));
                isTrue("CBC IV-only re-init " + forEncryption, Arrays.areEqual(expected, process(cbc, in)));
            }

            if (!forEncryption)
            {
                break;
            }
        }
    }

    /**
     * CBC uses the underlying cipher in both directions, so it cannot change direction without a key.
     */
    private void cbcDirectionChangeRefused()
    {
        byte[] key = randomBytes(16), iv = randomBytes(BLOCK_SIZE);
        CipherParameters[] reinits = { null, new ParametersWithIV(null, iv) };

        for (int r = 0; r != reinits.length; r++)
        {
            for (boolean forEncryption = true; ; forEncryption = false)
            {
                BlockCipher[] ciphers = cbcCiphers();
                for (int i = 0; i != ciphers.length; i++)
                {
                    BlockCipher cbc = ciphers[i];
                    cbc.init(forEncryption, new ParametersWithIV(new KeyParameter(key), iv));
                    try
                    {
                        cbc.init(!forEncryption, reinits[r]);
                        fail("CBC changed direction without a key");
                    }
                    catch (IllegalArgumentException e)
                    {
                        isEquals("cannot change encrypting state without providing key.", e.getMessage());
                    }
                }

                if (!forEncryption)
                {
                    break;
                }
            }
        }
    }

    /**
     * A key-only re-init of CFB uses the new key with the IV of the last init, unlike CBC.
     */
    private void cfbKeyOnlyReinit(int segment)
    {
        byte[] key1 = randomBytes(16), key2 = randomBytes(16), iv = randomBytes(BLOCK_SIZE);
        byte[] pt = randomBytes(segment * (1 + random.nextInt(40)));

        for (boolean forEncryption = true; ; forEncryption = false)
        {
            byte[] ct = refCFB(true, key2, iv, segment, pt);
            byte[] in = forEncryption ? pt : ct;
            byte[] expected = forEncryption ? ct : pt;

            BlockCipher[] ciphers = cfbCiphers(segment);
            for (int i = 0; i != ciphers.length; i++)
            {
                BlockCipher cfb = ciphers[i];
                cfb.init(forEncryption, new ParametersWithIV(new KeyParameter(key1), iv));
                process(cfb, randomBytes(segment * 3));

                cfb.init(forEncryption, new KeyParameter(key2));
                isTrue("CFB-" + segment * 8 + " key-only re-init " + forEncryption, Arrays.areEqual(expected, process(cfb, in)));

                // a zero IV, as CBC would use, must give a different answer.
                byte[] zeroIV = refCFB(forEncryption, key2, new byte[BLOCK_SIZE], segment, in);
                isTrue("CFB-" + segment * 8 + " key-only re-init zeroed IV " + forEncryption, !Arrays.areEqual(zeroIV, expected));
            }

            if (!forEncryption)
            {
                break;
            }
        }
    }

    /**
     * A null re-init of CFB keeps the key and the IV of the last init, and may change direction.
     */
    private void cfbNullReinit(int segment)
    {
        byte[] key = randomBytes(16), iv = randomBytes(BLOCK_SIZE);
        byte[] pt = randomBytes(segment * (1 + random.nextInt(40)));
        byte[] ct = refCFB(true, key, iv, segment, pt);

        for (int first = 0; first != 2; first++)
        {
            for (boolean forEncryption = true; ; forEncryption = false)
            {
                byte[] in = forEncryption ? pt : ct;
                byte[] expected = forEncryption ? ct : pt;

                BlockCipher[] ciphers = cfbCiphers(segment);
                for (int i = 0; i != ciphers.length; i++)
                {
                    BlockCipher cfb = ciphers[i];
                    cfb.init(first == 0, new ParametersWithIV(new KeyParameter(key), iv));
                    process(cfb, randomBytes(segment * 3));

                    cfb.init(forEncryption, null);
                    isTrue("CFB-" + segment * 8 + " null re-init " + (first == 0) + "->" + forEncryption,
                        Arrays.areEqual(expected, process(cfb, in)));
                }

                if (!forEncryption)
                {
                    break;
                }
            }
        }
    }

    /**
     * An IV-only re-init of CFB keeps the key and uses the new IV, and may change direction.
     */
    private void cfbIVOnlyReinit(int segment)
    {
        byte[] key = randomBytes(16), iv1 = randomBytes(BLOCK_SIZE), iv2 = randomBytes(BLOCK_SIZE);
        byte[] pt = randomBytes(segment * (1 + random.nextInt(40)));
        byte[] ct = refCFB(true, key, iv2, segment, pt);

        for (int first = 0; first != 2; first++)
        {
            for (boolean forEncryption = true; ; forEncryption = false)
            {
                byte[] in = forEncryption ? pt : ct;
                byte[] expected = forEncryption ? ct : pt;

                BlockCipher[] ciphers = cfbCiphers(segment);
                for (int i = 0; i != ciphers.length; i++)
                {
                    BlockCipher cfb = ciphers[i];
                    cfb.init(first == 0, new ParametersWithIV(new KeyParameter(key), iv1));
                    process(cfb, randomBytes(segment * 3));

                    cfb.init(forEncryption, new ParametersWithIV(null, iv2));
                    isTrue("CFB-" + segment * 8 + " IV-only re-init " + (first == 0) + "->" + forEncryption,
                        Arrays.areEqual(expected, process(cfb, in)));
                }

                if (!forEncryption)
                {
                    break;
                }
            }
        }
    }

    private static BlockCipher[] cbcCiphers()
    {
        return new BlockCipher[]{
            CBCBlockCipher.newInstance(new AESEngine()),
            CBCBlockCipher.newInstance(AESEngine.newInstance())
        };
    }

    private static BlockCipher[] cfbCiphers(int segment)
    {
        return new BlockCipher[]{
            CFBBlockCipher.newInstance(new AESEngine(), segment * 8),
            CFBBlockCipher.newInstance(AESEngine.newInstance(), segment * 8)
        };
    }

    /**
     * Process a whole number of blocks, with the block boundaries in a random mix of single-block
     * and multi-block calls.
     */
    private byte[] process(BlockCipher cipher, byte[] in)
    {
        int bs = cipher.getBlockSize();
        byte[] out = new byte[in.length];
        int off = 0;
        while (off < in.length)
        {
            if (cipher instanceof MultiBlockCipher && random.nextBoolean())
            {
                int blocks = 1 + random.nextInt((in.length - off) / bs);
                off += ((MultiBlockCipher)cipher).processBlocks(in, off, blocks, out, off);
            }
            else
            {
                off += cipher.processBlock(in, off, out, off);
            }
        }
        return out;
    }

    private static byte[] ecb(byte[] key, byte[] block)
    {
        AESEngine aes = new AESEngine();
        aes.init(true, new KeyParameter(key));
        byte[] out = new byte[BLOCK_SIZE];
        aes.processBlock(block, 0, out, 0);
        return out;
    }

    private static byte[] refCBCEncrypt(byte[] key, byte[] iv, byte[] pt)
    {
        byte[] out = new byte[pt.length];
        byte[] chain = Arrays.clone(iv);
        for (int off = 0; off != pt.length; off += BLOCK_SIZE)
        {
            byte[] block = new byte[BLOCK_SIZE];
            for (int j = 0; j != BLOCK_SIZE; j++)
            {
                block[j] = (byte)(pt[off + j] ^ chain[j]);
            }
            chain = ecb(key, block);
            System.arraycopy(chain, 0, out, off, BLOCK_SIZE);
        }
        return out;
    }

    private static byte[] refCBCDecrypt(byte[] key, byte[] iv, byte[] ct)
    {
        AESEngine aes = new AESEngine();
        aes.init(false, new KeyParameter(key));
        byte[] out = new byte[ct.length];
        byte[] chain = Arrays.clone(iv);
        for (int off = 0; off != ct.length; off += BLOCK_SIZE)
        {
            aes.processBlock(ct, off, out, off);
            for (int j = 0; j != BLOCK_SIZE; j++)
            {
                out[off + j] ^= chain[j];
            }
            chain = Arrays.copyOfRange(ct, off, off + BLOCK_SIZE);
        }
        return out;
    }

    /**
     * CFB with a segment of {@code segment} bytes, built on ECB: each segment is the input XOR the
     * leading bytes of E(register), and the register then shifts in the ciphertext segment.
     */
    private static byte[] refCFB(boolean forEncryption, byte[] key, byte[] iv, int segment, byte[] in)
    {
        byte[] out = new byte[in.length];
        byte[] register = Arrays.clone(iv);
        for (int off = 0; off != in.length; off += segment)
        {
            byte[] ks = ecb(key, register);
            for (int j = 0; j != segment; j++)
            {
                out[off + j] = (byte)(in[off + j] ^ ks[j]);
            }
            byte[] ct = forEncryption ? out : in;
            byte[] next = new byte[BLOCK_SIZE];
            System.arraycopy(register, segment, next, 0, BLOCK_SIZE - segment);
            System.arraycopy(ct, off, next, BLOCK_SIZE - segment, segment);
            register = next;
        }
        return out;
    }

    private byte[] randomBytes(int len)
    {
        byte[] b = new byte[len];
        random.nextBytes(b);
        return b;
    }

    public static void main(String[] args)
    {
        runTest(new ModeReinitTest());
    }
}
