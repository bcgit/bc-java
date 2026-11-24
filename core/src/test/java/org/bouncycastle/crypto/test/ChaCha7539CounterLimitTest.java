package org.bouncycastle.crypto.test;

import junit.framework.TestCase;
import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * ChaCha7539Engine at the end of its 32-bit block counter: RFC 8439 allows counter 0xFFFFFFFF, the stream may end
 * exactly after that block, and no keystream may follow it.
 */
public class ChaCha7539CounterLimitTest
    extends TestCase
{
    /*
     * Wycheproof chacha20_counter_test.json (C2SP/wycheproof), ChaCha20-IETF group: all-zero key and nonce, so the
     * ciphertext of an all-zero message is the keystream. tcId 35 starts at counter 0xFFFFFFFE (128 bytes); tcId 39
     * at 0xFFFFFFFF (64 bytes) is its second half. tcIds 40-42 (0xFFFFFFFF, 65 bytes or more) must be refused.
     */
    private static final String KEYSTREAM_FFFFFFFE =
        "032cc123482c31711f94c941af5ab1f4155784332ed5348fe79aec5ead4c06c3"
            + "f13c280d8cc49925e4a6a5922ec80e13a4cdfa840c70a1427a3cb699166991a5";
    private static final String KEYSTREAM_FFFFFFFF =
        "ace4cd09e294d1912d4ad205d06f95d9c2f2bfcf453e8753f128765b62215f4d"
            + "92c74f2f626c6a640c0b1284d839ec81f1696281dafc3e684593937023b58b1d";

    private static final long END = (1L << 32) * 64;

    private static ChaCha7539Engine engineAt(long position)
    {
        ChaCha7539Engine engine = new ChaCha7539Engine();
        engine.init(true, new ParametersWithIV(new KeyParameter(new byte[32]), new byte[12]));
        engine.seekTo(position);
        return engine;
    }

    private static byte[] process(ChaCha7539Engine engine, int length)
    {
        byte[] out = new byte[length];
        engine.processBytes(new byte[length], 0, length, out, 0);
        return out;
    }

    private static void assertRefused(ChaCha7539Engine engine, int length)
    {
        long position = engine.getPosition();
        byte[] out = new byte[length];
        Arrays.fill(out, (byte)0x55);
        try
        {
            engine.processBytes(new byte[length], 0, length, out, 0);
            fail("processed " + length + " bytes past the end of the counter");
        }
        catch (IllegalStateException e)
        {
            assertEquals("attempt to increase counter past 2^32.", e.getMessage());
        }

        byte[] untouched = new byte[length];
        Arrays.fill(untouched, (byte)0x55);
        assertTrue("output written by a refused call", Arrays.areEqual(untouched, out));
        assertEquals(position, engine.getPosition());
    }

    public void testLastBlockIsUsable()
    {
        ChaCha7539Engine engine = engineAt(END - 64);

        assertEquals(KEYSTREAM_FFFFFFFF, Hex.toHexString(process(engine, 64)));
        assertEquals(END, engine.getPosition());
    }

    public void testLastTwoBlocksAreUsable()
    {
        ChaCha7539Engine engine = engineAt(END - 128);

        assertEquals(KEYSTREAM_FFFFFFFE + KEYSTREAM_FFFFFFFF, Hex.toHexString(process(engine, 128)));
    }

    public void testLastBlockIsUsableByteByByte()
    {
        ChaCha7539Engine engine = engineAt(END - 64);

        byte[] out = new byte[64];
        for (int i = 0; i != out.length; i++)
        {
            out[i] = engine.returnByte((byte)0);
        }
        assertEquals(KEYSTREAM_FFFFFFFF, Hex.toHexString(out));

        try
        {
            engine.returnByte((byte)0);
            fail("returned a byte past the end of the counter");
        }
        catch (IllegalStateException e)
        {
            assertEquals("attempt to increase counter past 2^32.", e.getMessage());
        }
    }

    public void testUnalignedEnd()
    {
        ChaCha7539Engine engine = engineAt(END - 10);

        assertEquals(KEYSTREAM_FFFFFFFF.substring(108), Hex.toHexString(process(engine, 10)));
        assertRefused(engine, 1);
    }

    public void testPastTheEndIsRefusedWithoutOutput()
    {
        assertRefused(engineAt(END - 64), 65);
        assertRefused(engineAt(END - 64), 128);
        assertRefused(engineAt(END - 128), 129);
    }

    public void testExhaustedStaysRefused()
    {
        ChaCha7539Engine engine = engineAt(END - 64);
        process(engine, 64);

        // The counter word has wrapped to 0: any further keystream would repeat earlier blocks.
        assertRefused(engine, 1);
        assertRefused(engine, 64);
        assertEquals(END, engine.getPosition());
    }

    public void testSeekToTheEnd()
    {
        ChaCha7539Engine engine = engineAt(END);
        assertEquals(END, engine.getPosition());
        assertRefused(engine, 1);

        try
        {
            engine.skip(1);
            fail("skipped past the end of the counter");
        }
        catch (IllegalStateException e)
        {
            assertEquals("attempt to increase counter past 2^32.", e.getMessage());
        }

        try
        {
            engineAt(END + 1);
            fail("sought past the end of the counter");
        }
        catch (IllegalStateException e)
        {
            assertEquals("attempt to increase counter past 2^32.", e.getMessage());
        }
    }

    public void testSkipBackFromTheEnd()
    {
        ChaCha7539Engine engine = engineAt(END - 64);
        process(engine, 64);

        engine.skip(-64);
        assertEquals(END - 64, engine.getPosition());
        assertEquals(KEYSTREAM_FFFFFFFF, Hex.toHexString(process(engine, 64)));

        engine.skip(-1);
        assertEquals(END - 1, engine.getPosition());
        assertEquals(KEYSTREAM_FFFFFFFF.substring(126), Hex.toHexString(process(engine, 1)));

        engine.skip(-(END - 128));
        assertEquals(128, engine.getPosition());
    }

    public void testResetClearsTheExhaustedCounter()
    {
        ChaCha7539Engine engine = engineAt(END - 64);
        process(engine, 64);

        engine.reset();
        assertEquals(0, engine.getPosition());

        assertTrue(Arrays.areEqual(process(engineAt(0), 64), process(engine, 64)));
    }
}
