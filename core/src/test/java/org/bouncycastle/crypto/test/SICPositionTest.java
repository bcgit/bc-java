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

        // seek/skip across the 2^16-block carry region: the >255-block increment and
        // decrement cascades under adjustCounter, from and to mid-block positions
        checkSeekCascade(aesCipher(), params(aesKey, "000102030405060708090a0b0c0dFFFF"), 16);
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
