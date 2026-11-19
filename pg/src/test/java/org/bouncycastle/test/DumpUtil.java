package org.bouncycastle.test;

import org.bouncycastle.util.Pack;
import org.bouncycastle.util.encoders.Hex;

public class DumpUtil
{
    /**
     * Return a formatted hex dump of the given byte array.
     * @param array byte array
     */
    public static String hexdump(byte[] array)
    {
        return hexdump(0, array);
    }

    /**
     * Return a formatted hex dump of the given byte array.
     * If startIndent is non-zero, the dump is shifted right by startIndent octets.
     * @param startIndent shift the octet stream between by a number of bytes
     * @param array byte array
     */
    public static String hexdump(int startIndent, byte[] array)
    {
        if (startIndent < 0)
        {
            throw new IllegalArgumentException("'startIndent' must be a positive number");
        }
        if (array == null)
        {
            return "<null>";
        }

        // The first startIndent positions are blank, shifting the bytes right
        int count = startIndent + array.length;

        StringBuilder out = new StringBuilder();
        for (int row = 0; row < count; row += 16)
        {
            // -DM Hex.toHexString
            out.append(Hex.toHexString(Pack.intToBigEndian(row))).append(' ');

            int rowEnd = Math.min(row + 16, count);
            for (int i = row; i < rowEnd; ++i)
            {
                if (i == row + 8)
                {
                    out.append(' ');
                }

                out.append(' ').append(i < startIndent ? "  " : HEX_PAIRS[array[i - startIndent] & 0xFF]);
            }
            out.append('\n');
        }
        return out.toString();
    }

    private static final String[] HEX_PAIRS = createHexPairs();

    private static String[] createHexPairs()
    {
        String[] hexPairs = new String[256];
        for (int i = 0; i < 256; ++i)
        {
            // -DM Hex.toHexString
            hexPairs[i] = Hex.toHexString(new byte[]{ (byte)i });
        }
        return hexPairs;
    }
}
