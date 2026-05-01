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
            throw new IllegalArgumentException("Start-Indent must be a positive number");
        }
        if (array == null)
        {
            return "<null>";
        }

        // -DM Hex.toHexString
        String hex = Hex.toHexString(array);
        StringBuffer withWhiteSpace = new StringBuffer();
        // shift the dump a number of octets to the right
        for (int i = 0; i < startIndent; i++)
        {
            withWhiteSpace.append("  ");
        }
        // Split into hex octets (pairs of two chars)

        String base = withWhiteSpace.append(hex).toString();
        String[] octets = new String[hex.length() / 2];
        int start = startIndent + 2;
        octets[0] = base.substring(0, start);
        for (int i = 1; i != octets.length; i++)
        {
            octets[i] = base.substring(start, start + 2);
            start += 2;
        }

        StringBuffer out = new StringBuffer();
        int l = 0;
        byte[] counterLabel = new byte[4];

        while (l < octets.length)
        {
            // index row
            Pack.intToBigEndian(l, counterLabel, 0);
            out.append(Hex.toHexString(counterLabel)).append("  ");
            // first 8 octets of a line
            for (int i = l ; i < l + 8 && i < octets.length; i++)
            {
                out.append(octets[i]).append(" ");
            }
            out.append(" ");
            // second 8 octets of a line
            for (int i = l+8; i < l + 16 && i < octets.length; i++)
            {
                out.append(octets[i]).append(" ");
            }
            out.append("\n");

            l += 16;
        }
        return out.toString();
    }
}
