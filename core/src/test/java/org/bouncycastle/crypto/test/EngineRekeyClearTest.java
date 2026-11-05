package org.bouncycastle.crypto.test;

import java.lang.reflect.Field;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.AESLightEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Re-keying the AES and DES engines clears the key schedule they held before, rather than leaving it in
 * memory for the collector, and the engine then works under the new key.
 */
public class EngineRekeyClearTest
    extends SimpleTest
{
    private static final byte[] KEY_A = Hex.decode("000102030405060708090a0b0c0d0e0f1011121314151617");
    private static final byte[] KEY_B = Hex.decode("f0e1d2c3b4a5968778695a4b3c2d1e0f0123456789abcdef");

    public String getName()
    {
        return "EngineRekeyClear";
    }

    public void performTest()
        throws Exception
    {
        checkEngine(new AESEngine(), new AESEngine(), "WorkingKey", 16);
        checkEngine(new AESLightEngine(), new AESLightEngine(), "WorkingKey", 16);
        checkEngine(new AESFastEngine(), new AESFastEngine(), "WorkingKey", 16);
        checkEngine(new DESEngine(), new DESEngine(), "workingKey", 8);
        checkEngine(new DESedeEngine(), new DESedeEngine(), "workingKey1", 24);
        checkEngine(new DESedeEngine(), new DESedeEngine(), "workingKey2", 24);
        checkEngine(new DESedeEngine(), new DESedeEngine(), "workingKey3", 24);
        checkEngine(new DESedeEngine(), new DESedeEngine(), "workingKey1", 16);
    }

    private void checkEngine(BlockCipher engine, BlockCipher fresh, String fieldName, int keyLen)
        throws Exception
    {
        engine.init(true, new KeyParameter(KEY_A, 0, keyLen));
        Object before = getField(engine, fieldName);

        engine.init(true, new KeyParameter(KEY_B, 0, keyLen));
        Object after = getField(engine, fieldName);

        isTrue(engine.getAlgorithmName() + " " + fieldName + " reused on re-key", before != after);
        isTrue(engine.getAlgorithmName() + " " + fieldName + " not cleared on re-key", isCleared(before));

        // the re-keyed engine agrees with a fresh engine under the new key
        fresh.init(true, new KeyParameter(KEY_B, 0, keyLen));
        byte[] in = new byte[engine.getBlockSize()];
        byte[] out1 = new byte[in.length];
        byte[] out2 = new byte[in.length];
        engine.processBlock(in, 0, out1, 0);
        fresh.processBlock(in, 0, out2, 0);
        isTrue(engine.getAlgorithmName() + " output wrong after re-key", Arrays.areEqual(out1, out2));
    }

    private static Object getField(Object engine, String fieldName)
        throws Exception
    {
        Field f = engine.getClass().getDeclaredField(fieldName);
        f.setAccessible(true);
        return f.get(engine);
    }

    private static boolean isCleared(Object schedule)
    {
        if (schedule instanceof int[][])
        {
            int[][] rows = (int[][])schedule;
            for (int i = 0; i != rows.length; i++)
            {
                if (!isCleared(rows[i]))
                {
                    return false;
                }
            }
            return true;
        }

        int[] row = (int[])schedule;
        for (int i = 0; i != row.length; i++)
        {
            if (row[i] != 0)
            {
                return false;
            }
        }
        return true;
    }

    public static void main(String[] args)
    {
        runTest(new EngineRekeyClearTest());
    }
}
