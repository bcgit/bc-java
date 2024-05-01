package org.bouncycastle.bcpg.test;

import org.bouncycastle.bcpg.ContainedPacket;
import org.bouncycastle.test.DumpUtil;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.SimpleTest;

import java.io.IOException;

public abstract class AbstractPacketTest
        extends SimpleTest
{

    /**
     * Test, whether the first byte array and the second byte array are identical.
     * If a mismatch is detected, a formatted hex dump of both arrays is printed to stdout.
     * @param first first array
     * @param second second array
     */
    public void isEncodingEqual(byte[] first, byte[] second)
    {
        isEncodingEqual(null, first, second);
    }

    /**
     * Test, whether the first byte array and the second byte array are identical.
     * If a mismatch is detected, a formatted hex dump of both arrays is printed to stdout.
     * @param message error message to prepend to the hex dump
     * @param first first array
     * @param second second array
     */
    public void isEncodingEqual(String message, byte[] first, byte[] second)
    {
        StringBuilder sb = new StringBuilder();
        if (message != null)
        {
            sb.append(message).append("\n");
        }
        sb.append("Expected: \n").append(DumpUtil.hexdump(first)).append("\n");
        sb.append("Got: \n").append(DumpUtil.hexdump(second));

        isTrue(sb.toString(), first == second || Arrays.areEqual(first, second));
    }

    /**
     * Test, whether the encoding of the first and second packet are identical.
     * If a mismatch is detected, a formatted hex dump of both packet encodings is printed to stdout.
     * @param first first packet
     * @param second second packet
     */
    public void isEncodingEqual(ContainedPacket first, ContainedPacket second)
            throws IOException
    {
        isEncodingEqual(null, first, second);
    }

    /**
     * Test, whether the encoding of the first and second packet are identical.
     * If a mismatch is detected, a formatted hex dump of both packet encodings is printed to stdout.
     * @param message error message to prepend to the hex dump
     * @param first first packet
     * @param second second packet
     */
    public void isEncodingEqual(String message, ContainedPacket first, ContainedPacket second)
            throws IOException
    {
        StringBuilder sb = new StringBuilder();
        if (message != null)
        {
            sb.append(message).append("\n");
        }
        sb.append("Expected: \n").append(PacketDumpUtil.hexdump(first)).append("\n");
        sb.append("Got: \n").append(PacketDumpUtil.hexdump(second));
        isTrue(sb.toString(), first == second || Arrays.areEqual(first.getEncoded(), second.getEncoded()));
    }

    /**
     * Test, whether the value is false.
     * @param value value
     */
    public void isFalse(boolean value)
    {
        isFalse("Value is not false.", value);
    }

    /**
     * Test, whether the value is false.
     * @param message custom error message
     * @param value value
     */
    public void isFalse(String message, boolean value)
    {
        isTrue(message, !value);
    }

    /**
     * Test, whether the value is null.
     * @param value value
     */
    public void isNull(Object value)
    {
        isNull("Value is not null.", value);
    }

    /**
     * Test, whether the value is null.
     * @param message custom error message
     * @param value value
     */
    public void isNull(String message, Object value)
    {
        isTrue(message, value == null);
    }

    /**
     * Test, whether the value is not null.
     * @param value value
     */
    public void isNotNull(Object value)
    {
        isNotNull("Value is not null.", value);
    }

    /**
     * Test, whether the value is not null.
     * @param message custom error message
     * @param value value
     */
    public void isNotNull(String message, Object value)
    {
        isTrue(message, value != null);
    }
}
