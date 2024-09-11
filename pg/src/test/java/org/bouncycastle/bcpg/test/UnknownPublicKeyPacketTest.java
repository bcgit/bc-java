package org.bouncycastle.bcpg.test;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.PacketFormat;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.UnknownBCPGKey;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

public class UnknownPublicKeyPacketTest
    extends AbstractPacketTest
{
    private final String[]  testVectors = {"c61406665ef5f3630000000a00010203040506070809", "c61405665ef5f3630000000a00010203040506070809"};
    private final int[]     versions    = {PublicKeyPacket.VERSION_6,                       PublicKeyPacket.LIBREPGP_5};      

    @Override
    public String getName()
    {
        return "UnknownPublicKeyPacketTest";
    }

    @Override
    public void performTest()
        throws Exception
    {
        parseUnknownPublicKey();
    }

    private void parseUnknownPublicKey()
            throws ParseException, IOException
    {
        SimpleDateFormat parser = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z");
        parser.setTimeZone(TimeZone.getTimeZone("UTC"));

        for (int i = 0; i < testVectors.length; i++)
        {
            String testVector = testVectors[i];
            byte[] rawKey = new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
            Date creationTime = parser.parse("2024-06-04 11:09:39 UTC");

            PublicKeyPacket p = new PublicKeyPacket(
                versions[i],
                99,
                creationTime,
                new UnknownBCPGKey(10, rawKey));
            isEncodingEqual("Encoding mismatch", Hex.decode(testVector), p.getEncoded(PacketFormat.CURRENT));

            ByteArrayInputStream bIn = new ByteArrayInputStream(Hex.decode(testVector));
            BCPGInputStream pIn = new BCPGInputStream(bIn);
            PublicKeyPacket parsed = (PublicKeyPacket) pIn.readPacket();
            isEquals("Packet version mismatch", versions[i], parsed.getVersion());
            isEquals("Public key algorithm mismatch", 99, parsed.getAlgorithm());
            isEquals("Creation time mismatch", creationTime, parsed.getTime());
            isEncodingEqual("Raw key encoding mismatch", rawKey, parsed.getKey().getEncoded());
        }
    }

    public static void main(String[] args)
    {
        runTest(new UnknownPublicKeyPacketTest());
    }
}