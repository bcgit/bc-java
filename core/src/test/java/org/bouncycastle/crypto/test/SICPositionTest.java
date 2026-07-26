package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.modes.CTRModeCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Regression test for SICBlockCipher position tracking (getPosition/seekTo/skip)
 * around counter-increment carries. getPosition() used to apply the borrow in its
 * counter-minus-IV subtraction as a raw byte decrement, dropping the borrow when the
 * decremented byte wrapped 0x00 to 0xFF - i.e. once an increment had carried across
 * consecutive 0xFF IV bytes - and it never subtracted IV[0], so 8-byte block ciphers
 * with a full-length IV reported a position offset by IV[0] * 2^56 blocks. Also
 * covers skip() from mid-block positions: a backward skip smaller than the intra-block
 * offset used to rewind to the block start instead of moving exactly |n| bytes.
 * <p>
 * Also covers the full-block IV counter-range bound: the advance since init is limited to
 * 2^64 blocks (one carry past the low 8-byte lane is legal, reaching 2^64 blocks throws),
 * a backward move below the initial counter throws, and the short-IV counter-space check
 * fires on the processBlock() path as well as processBytes().
 */
public class SICPositionTest
    extends SimpleTest
{
    public String getName()
    {
        return "SICPosition";
    }

    public void performTest()
    {
        byte[] aesKey = Hex.decode("5F060D3716B345C253F6749ABAC10917");
        byte[] desKey = Hex.decode("0123456789abcdef");

        // full-block AES IVs whose counter increments carry across trailing 0xFF bytes
        checkPositionTracking(aesCipher(), params(aesKey, "000102030405060708090a0b0c0dFFFF"), 16);
        checkPositionTracking(aesCipher(), params(aesKey, "00010203040506070809FFFFFFFFFFFF"), 16);
        checkPositionTracking(aesCipher(), params(aesKey, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"), 16);

        // controls: no carry into a zero byte, and a partial (nonce-style) IV
        checkPositionTracking(aesCipher(), params(aesKey, "000102030405060708090a0b0c0d0e0f"), 16);
        checkPositionTracking(aesCipher(), params(aesKey, "0001020304050607"), 16);

        // 8-byte block cipher: all 8 bytes of counter - IV are significant, so a
        // full-length IV exercises the IV[0] term as well as the borrow chain
        checkPositionTracking(desCipher(), params(desKey, "0102030405060708"), 8);
        checkPositionTracking(desCipher(), params(desKey, "01020304FFFFFFFF"), 8);
        checkPositionTracking(desCipher(), params(desKey, "FFFFFFFFFFFFFFFF"), 8);

        // full-block IV whose low 8-byte lane is all 0xFF: the single legal carry past the
        // lane happens at the second block
        checkPositionTracking(aesCipher(), params(aesKey, "0011223344556677FFFFFFFFFFFFFFFF"), 16);

        // seek/skip across the 2^16-block carry region: the >255-block increment and
        // decrement cascades under adjustCounter, from and to mid-block positions
        checkSeekCascade(aesCipher(), params(aesKey, "000102030405060708090a0b0c0dFFFF"), 16);

        // full-block IV counter-range enforcement
        checkFullBlockRangeBySkip(aesKey, "8899aabbccddeeff0000000000000000");    // no legal carry
        checkFullBlockRangeBySkip(aesKey, "8899aabbccddeeffFFFFFFFFFFFFFFFF");    // carry at block 1
        checkFullBlockRangeAtGeneration(aesKey);
        checkBackwardSkipBelowStart(aesKey);
        checkShortIVProcessBlockRange(aesKey);

        // skip() at the extremes of the long range
        checkSkipLongMinValue(aesKey, "000102030405060708090a0b0c0d0e0f");        // full-block IV
        checkSkipLongMinValue(aesKey, "0001020304050607");                        // partial IV
        checkSkipNearLongMaxValue(aesKey);
    }

    private static final String OUT_OF_RANGE = "Counter in CTR/SIC mode out of range.";
    private static final long SKIP_CHUNK = 1L << 62;   // 2^58 AES blocks per skip

    // accumulated skips reaching 2^64 blocks from init must throw, whether or not the
    // counter legally carried past the low 8-byte lane on the way; afterwards the cipher
    // refuses to produce output until re-initialised
    private void checkFullBlockRangeBySkip(byte[] aesKey, String iv)
    {
        CTRModeCipher cipher = aesCipher();
        cipher.init(true, params(aesKey, iv));

        int skips = 0;
        try
        {
            // 2^64 blocks = 64 chunks of 2^58 blocks; the 64th crosses the bound
            for (; skips != 70; skips++)
            {
                cipher.skip(SKIP_CHUNK);
            }
            fail("skip past 2^64 blocks did not throw (iv " + iv + ")");
        }
        catch (IllegalStateException e)
        {
            isTrue("wrong message: " + e.getMessage(), OUT_OF_RANGE.equals(e.getMessage()));
            isTrue("threw after " + skips + " skips", skips == 63);
        }

        // the failure is sticky for output...
        byte[] block = new byte[16];
        try
        {
            cipher.processBytes(block, 0, block.length, block, 0);
            fail("processBytes after range failure did not throw");
        }
        catch (IllegalStateException e)
        {
            isTrue("wrong message: " + e.getMessage(), OUT_OF_RANGE.equals(e.getMessage()));
        }

        // ...until the cipher is re-initialised
        cipher.init(true, params(aesKey, iv));
        cipher.processBytes(block, 0, block.length, block, 0);
        if (cipher.getPosition() != 16)
        {
            fail("position after recovery incorrect: got " + cipher.getPosition());
        }
    }

    // the bound is enforced lazily: blocks 2^64 - 2 and 2^64 - 1 are still produced,
    // the first byte of block 2^64 throws
    private void checkFullBlockRangeAtGeneration(byte[] aesKey)
    {
        CTRModeCipher cipher = aesCipher();
        cipher.init(true, params(aesKey, "8899aabbccddeeff0000000000000000"));

        // 63 chunks of 2^58 blocks, then 2^58 - 2 blocks: 2^64 - 2 blocks in total
        for (int i = 0; i != 63; i++)
        {
            cipher.skip(SKIP_CHUNK);
        }
        cipher.skip(SKIP_CHUNK - 32);

        byte[] block = new byte[16];
        cipher.processBytes(block, 0, block.length, block, 0);   // block 2^64 - 2
        cipher.processBytes(block, 0, block.length, block, 0);   // block 2^64 - 1

        try
        {
            cipher.processBytes(block, 0, 1, block, 0);
            fail("generation at block 2^64 did not throw");
        }
        catch (IllegalStateException e)
        {
            isTrue("wrong message: " + e.getMessage(), OUT_OF_RANGE.equals(e.getMessage()));
        }
    }

    // a backward move below the initial counter must throw rather than silently wrapping
    private void checkBackwardSkipBelowStart(byte[] aesKey)
    {
        CTRModeCipher cipher = aesCipher();
        cipher.init(true, params(aesKey, "000102030405060708090a0b0c0d0e0f"));

        try
        {
            cipher.skip(-16);
            fail("skip below the initial counter did not throw");
        }
        catch (IllegalStateException e)
        {
            isTrue("wrong message: " + e.getMessage(), OUT_OF_RANGE.equals(e.getMessage()));
        }
    }

    // skip(Long.MIN_VALUE): -n overflows back to Long.MIN_VALUE in adjustCounter's negative
    // branch, which used to leave the residual decrement loop counting through the whole long
    // range - run on a watchdog thread so a regression fails the test instead of wedging the
    // suite. The move itself lands far below the initial counter, so the range check throws.
    private void checkSkipLongMinValue(byte[] aesKey, String iv)
    {
        final CTRModeCipher cipher = aesCipher();
        cipher.init(true, params(aesKey, iv));

        final Throwable[] outcome = new Throwable[1];
        final boolean[] returned = new boolean[1];

        Thread worker = new Thread(new Runnable()
        {
            public void run()
            {
                try
                {
                    cipher.skip(Long.MIN_VALUE);
                }
                catch (Throwable e)
                {
                    outcome[0] = e;
                }
                returned[0] = true;
            }
        });
        worker.setDaemon(true);
        worker.start();
        try
        {
            worker.join(20000);
        }
        catch (InterruptedException e)
        {
            Thread.currentThread().interrupt();
        }

        isTrue("skip(Long.MIN_VALUE) did not return (iv " + iv + ")", returned[0]);
        isTrue("skip(Long.MIN_VALUE) should land below the initial counter (iv " + iv + ")",
            outcome[0] instanceof IllegalStateException && OUT_OF_RANGE.equals(outcome[0].getMessage()));
    }

    // a forward skip whose target overflows (n + byteCount) from a mid-block position: the
    // counter must still land exactly (verified by skipping back and comparing keystream),
    // even though the byte position itself is no longer representable in a long
    private void checkSkipNearLongMaxValue(byte[] aesKey)
    {
        String iv = "000102030405060708090a0b0c0d0e0f";

        CTRModeCipher cipher = aesCipher();
        cipher.init(true, params(aesKey, iv));

        byte[] zeroes = new byte[32];
        byte[] keyStream = new byte[32];
        cipher.processBytes(zeroes, 0, 32, keyStream, 0);

        cipher.init(true, params(aesKey, iv));
        byte[] fragment = new byte[16];
        cipher.processBytes(zeroes, 0, 15, fragment, 0);

        long n = Long.MAX_VALUE - 7;    // 15 + n overflows a long

        cipher.skip(n);
        cipher.skip(-n);

        if (cipher.getPosition() != 15)
        {
            fail("extreme forward/back skip landed at " + cipher.getPosition());
        }

        cipher.processBytes(zeroes, 0, 16, fragment, 0);

        if (!areEqual(fragment, 0, 16, keyStream, 15, 31))
        {
            fail("keystream after extreme forward/back skip mismatch");
        }
    }

    // a 15-byte IV leaves one counter byte (256 blocks); the range check must fire on the
    // processBlock() path too, which used to run unchecked
    private void checkShortIVProcessBlockRange(byte[] aesKey)
    {
        CTRModeCipher cipher = aesCipher();
        cipher.init(true, params(aesKey, "000102030405060708090a0b0c0d0e"));

        byte[] in = new byte[16];
        byte[] out = new byte[16];

        for (int i = 0; i != 256; i++)
        {
            cipher.processBlock(in, 0, out, 0);
        }

        try
        {
            cipher.processBlock(in, 0, out, 0);
            fail("processBlock past the counter space did not throw");
        }
        catch (IllegalStateException e)
        {
            isTrue("wrong message: " + e.getMessage(), OUT_OF_RANGE.equals(e.getMessage()));
        }
    }

    private CTRModeCipher aesCipher()
    {
        return SICBlockCipher.newInstance(AESEngine.newInstance());
    }

    private CTRModeCipher desCipher()
    {
        return SICBlockCipher.newInstance(new DESEngine());
    }

    private CipherParameters params(byte[] key, String iv)
    {
        return new ParametersWithIV(new KeyParameter(key), Hex.decode(iv));
    }

    private void checkPositionTracking(CTRModeCipher cipher, CipherParameters params, int blockSize)
    {
        int totalLen = 5 * blockSize;
        byte[] zeroes = new byte[totalLen];
        byte[] keyStream = new byte[totalLen];

        cipher.init(true, params);
        cipher.processBytes(zeroes, 0, totalLen, keyStream, 0);

        // position bookkeeping while processing linearly, including mid-block
        cipher.init(true, params);

        byte[] oneByte = new byte[1];
        for (int n = 0; n != totalLen; n++)
        {
            if (cipher.getPosition() != n)
            {
                fail("position at byte " + n + " incorrect: got " + cipher.getPosition());
            }

            cipher.processBytes(zeroes, n, 1, oneByte, 0);
        }

        if (cipher.getPosition() != totalLen)
        {
            fail("final position incorrect: got " + cipher.getPosition());
        }

        // seekTo: reported position and produced keystream must both agree
        byte[] fragment = new byte[blockSize];
        for (int pos = 0; pos <= totalLen - blockSize; pos++)
        {
            cipher.init(true, params);

            long sought = cipher.seekTo(pos);
            if (sought != pos)
            {
                fail("seekTo(" + pos + ") returned " + sought);
            }

            if (cipher.getPosition() != pos)
            {
                fail("seekTo(" + pos + ") reported position " + cipher.getPosition());
            }

            cipher.processBytes(zeroes, 0, blockSize, fragment, 0);

            if (!areEqual(fragment, 0, blockSize, keyStream, pos, pos + blockSize))
            {
                fail("seekTo(" + pos + ") keystream mismatch");
            }

            if (cipher.getPosition() != pos + blockSize)
            {
                fail("position after fragment at " + pos + " incorrect: got " + cipher.getPosition());
            }
        }

        // skip back and forth across the carry region
        cipher.init(true, params);

        long moved = cipher.skip(2 * blockSize);
        if (moved != 2 * blockSize)
        {
            fail("skip(" + (2 * blockSize) + ") returned " + moved);
        }

        if (cipher.getPosition() != 2 * blockSize)
        {
            fail("skip forward position incorrect: got " + cipher.getPosition());
        }

        moved = cipher.skip(-blockSize);
        if (moved != -blockSize)
        {
            fail("skip(" + (-blockSize) + ") returned " + moved);
        }

        if (cipher.getPosition() != blockSize)
        {
            fail("skip back position incorrect: got " + cipher.getPosition());
        }

        cipher.processBytes(zeroes, 0, blockSize, fragment, 0);

        if (!areEqual(fragment, 0, blockSize, keyStream, blockSize, 2 * blockSize))
        {
            fail("keystream after skip back mismatch");
        }

        // mid-block skips: a backward skip smaller than the intra-block offset must
        // move exactly |n| bytes - adjustCounter's negative path used to rewind to
        // the block start (byteCount = 0) whenever the target lay inside the current
        // block, while skip() still returned |n| as if the move were exact
        int half = blockSize / 2;

        cipher.init(true, params);
        cipher.processBytes(zeroes, 0, half + 1, fragment, 0);

        moved = cipher.skip(-1);
        if (moved != -1)
        {
            fail("mid-block skip(-1) returned " + moved);
        }

        if (cipher.getPosition() != half)
        {
            fail("mid-block skip(-1) from " + (half + 1) + " landed at " + cipher.getPosition());
        }

        cipher.processBytes(zeroes, 0, blockSize, fragment, 0);

        if (!areEqual(fragment, 0, blockSize, keyStream, half, half + blockSize))
        {
            fail("keystream after mid-block skip(-1) mismatch");
        }

        // forward from mid-block, crossing a block boundary
        moved = cipher.skip(blockSize + 1);
        if (moved != blockSize + 1)
        {
            fail("mid-block skip(" + (blockSize + 1) + ") returned " + moved);
        }

        int expected = half + 2 * blockSize + 1;
        if (cipher.getPosition() != expected)
        {
            fail("mid-block forward skip landed at " + cipher.getPosition() + " expected " + expected);
        }

        cipher.processBytes(zeroes, 0, blockSize, fragment, 0);

        if (!areEqual(fragment, 0, blockSize, keyStream, expected, expected + blockSize))
        {
            fail("keystream after mid-block forward skip mismatch");
        }

        // backward from mid-block across a block boundary (borrows a block back)
        moved = cipher.skip(-(blockSize + 2));
        if (moved != -(blockSize + 2))
        {
            fail("mid-block skip(" + (-(blockSize + 2)) + ") returned " + moved);
        }

        expected = half + 2 * blockSize - 1;
        if (cipher.getPosition() != expected)
        {
            fail("mid-block backward skip landed at " + cipher.getPosition() + " expected " + expected);
        }

        cipher.processBytes(zeroes, 0, blockSize, fragment, 0);

        if (!areEqual(fragment, 0, blockSize, keyStream, expected, expected + blockSize))
        {
            fail("keystream after mid-block backward skip mismatch");
        }
    }

    private void checkSeekCascade(CTRModeCipher cipher, CipherParameters params, int blockSize)
    {
        // 65537 blocks crosses the 2^16-block carry region for an IV ending FFFF;
        // two blocks of slack for the mid-block fragments read back afterwards
        int totalLen = 65539 * blockSize;
        byte[] zeroes = new byte[totalLen];
        byte[] keyStream = new byte[totalLen];

        cipher.init(true, params);
        cipher.processBytes(zeroes, 0, totalLen, keyStream, 0);

        // mid-block seek through the >255-block increment cascade
        byte[] fragment = new byte[blockSize];
        int seekPos = 65537 * blockSize + 5;

        cipher.init(true, params);

        long ret = cipher.seekTo(seekPos);
        if (ret != seekPos)
        {
            fail("cascade seekTo(" + seekPos + ") returned " + ret);
        }

        if (cipher.getPosition() != seekPos)
        {
            fail("cascade seekTo(" + seekPos + ") reported position " + cipher.getPosition());
        }

        cipher.processBytes(zeroes, 0, blockSize, fragment, 0);

        if (!areEqual(fragment, 0, blockSize, keyStream, seekPos, seekPos + blockSize))
        {
            fail("keystream after cascade seek mismatch");
        }

        // long mid-block backward skip: the >255-block decrement cascade walks the
        // counter back across the carry boundary, then the intra-block gap borrows
        // one more block
        long back = -(65537L * blockSize);

        ret = cipher.skip(back);
        if (ret != back)
        {
            fail("cascade skip(" + back + ") returned " + ret);
        }

        int landed = blockSize + 5;
        if (cipher.getPosition() != landed)
        {
            fail("cascade skip back landed at " + cipher.getPosition() + " expected " + landed);
        }

        cipher.processBytes(zeroes, 0, blockSize, fragment, 0);

        if (!areEqual(fragment, 0, blockSize, keyStream, landed, landed + blockSize))
        {
            fail("keystream after cascade skip back mismatch");
        }
    }

    public static void main(String[] args)
    {
        runTest(new SICPositionTest());
    }
}
