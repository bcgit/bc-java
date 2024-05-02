package org.bouncycastle.bcpg.test;

import java.io.IOException;

import org.bouncycastle.bcpg.ContainedPacket;
import org.bouncycastle.test.DumpUtil;

public class PacketDumpUtil
{
    /**
        * Return a formatted hex dump of the packet encoding of the given packet.
        * @param packet packet
        * @return formatted hex dump
        * @throws IOException if an exception happens during packet encoding
        */
       public static String hexdump(ContainedPacket packet)
               throws IOException
       {
           return DumpUtil.hexdump(packet.getEncoded());
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
           return DumpUtil.hexdump(startIndent, packet.getEncoded());
       }
}
