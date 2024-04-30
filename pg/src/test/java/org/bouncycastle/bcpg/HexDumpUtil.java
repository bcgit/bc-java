package org.bouncycastle.bcpg;

import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;

public class HexDumpUtil
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
        String hex = Hex.toHexString(array);
        StringBuilder withWhiteSpace = new StringBuilder();
        // shift the dump a number of octets to the right
        for (int i = 0; i < startIndent; i++)
        {
            withWhiteSpace.append("  ");
        }
        // Split into hex octets (pairs of two chars)
        String[] octets = withWhiteSpace.append(hex).toString().split("(?<=\\G.{2})");

        StringBuilder out = new StringBuilder();
        int l = 0;
        while (l < octets.length)
        {
            // index row
            out.append(String.format("%08X", l)).append("  ");
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

    /**
     * Return a formatted hex dump of the packet encoding of the given packet.
     * @param packet packet
     * @return formatted hex dump
     * @throws IOException if an exception happens during packet encoding
     */
    public static String hexdump(ContainedPacket packet)
            throws IOException
    {
        return hexdump(packet.getEncoded());
    }

    /**
     * Return a formatted hex dump of the packet encoding of the given packet.
     * If startIndent is non-zero, the hex dump is shifted right by the startIndent octets.
     * @param startIndent shift the encodings octet stream by a number of bytes
     * @param packet packet
     * @return formatted hex dump
     * @throws IOException if an exception happens during packet encoding
     */
    public static String hexdump(int startIndent, ContainedPacket packet)
            throws IOException
    {
        return hexdump(startIndent, packet.getEncoded());
    }
}
