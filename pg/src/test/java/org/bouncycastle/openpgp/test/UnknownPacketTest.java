package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.UnknownPacket;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

import java.io.ByteArrayInputStream;
import java.io.IOException;

public class UnknownPacketTest
        extends SimpleTest
{


    @Override
    public String getName()
    {
        return "UnknownPacketTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        // Test encoding
        testUnknownCriticalPacket();
        testUnknownNonCriticalPacket();

        // Test parsing with PGPObjectFactory
        testParseNonCriticalPacket();
        testParseCriticalPacketWithThrowing();
        testParseCriticalPacketWithoutThrowing();
    }

    private void testUnknownCriticalPacket()
            throws IOException
    {
        int tag = 39; // within critical range
        byte[] contents = new byte[] {0x50, 0x47, 0x50, 0x61, 0x69, 0x6e, 0x6c, 0x65, 0x73, 0x73};
        ByteArrayInputStream bIn = new ByteArrayInputStream(contents);
        BCPGInputStream bcIn = new BCPGInputStream(bIn);
        UnknownPacket packet = new UnknownPacket(tag, bcIn);

        isTrue(packet.isCritical());
        testPacketEncoding(tag, contents, packet);
    }

    private void testUnknownNonCriticalPacket()
            throws IOException
    {
        int tag = 44; // within non-critical range
        byte[] contents = new byte[] {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
        ByteArrayInputStream bIn = new ByteArrayInputStream(contents);
        BCPGInputStream bcIn = new BCPGInputStream(bIn);
        UnknownPacket packet = new UnknownPacket(tag, bcIn);

        isTrue(!packet.isCritical());
        testPacketEncoding(tag, contents, packet);
    }

    private void testPacketEncoding(int tag, byte[] contents, UnknownPacket packet)
            throws IOException
    {
        byte[] encoded = packet.getEncoded();

        int hdr = encodeTag(tag);
        isEquals(hdr, encoded[0] & 0xff);
        isEquals(contents.length, encoded[1]);
        for (int i = 0; i < contents.length; i++)
        {
            isEquals(encoded[i + 2], contents[i]);
        }
    }

    private int encodeTag(int tag)
    {
        int hdr = 0x80;
        hdr |= 0x40 | tag;
        return hdr & 0xff;
    }

    private void testParseNonCriticalPacket()
            throws IOException
    {
        int tag = 44;
        String encodedCriticalPacket = "ec0e4f70656e50475020726f636b7321"; // Tag 36
        ByteArrayInputStream in = new ByteArrayInputStream(Hex.decode(encodedCriticalPacket));

        PGPObjectFactory objectFactory = new BcPGPObjectFactory(in);
        UnknownPacket packet = (UnknownPacket) objectFactory.nextObject();
        isEquals(tag, packet.getPacketTag());
        isTrue(!packet.isCritical());
    }

    private void testParseCriticalPacketWithoutThrowing()
            throws IOException
    {
        int tag = 36;
        String encodedCriticalPacket = "e40e4f70656e50475020726f636b7321"; // Tag 36
        ByteArrayInputStream in = new ByteArrayInputStream(Hex.decode(encodedCriticalPacket));

        PGPObjectFactory objectFactory = new BcPGPObjectFactory(in);
        UnknownPacket packet = (UnknownPacket) objectFactory.nextObject();
        isEquals(tag, packet.getPacketTag());
        isTrue(packet.isCritical());
    }

    private void testParseCriticalPacketWithThrowing()
    {
        String encodedCriticalPacket = "e40e4f70656e50475020726f636b7321"; // Tag 36
        ByteArrayInputStream in = new ByteArrayInputStream(Hex.decode(encodedCriticalPacket));

        PGPObjectFactory objectFactory = new BcPGPObjectFactory(in)
                .setThrowForUnknownCriticalPackets(true); // Enable exception throwing for unknown critical packets
        try
        {
            objectFactory.nextObject();
            fail("Expected IOException, but nothing was thrown");
        }
        catch (IOException e)
        {
            // expected
        }
    }

    public static void main(String[] args)
    {
        runTest(new UnknownPacketTest());
    }
}
