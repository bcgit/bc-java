package org.bouncycastle.bcpg.test;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.PacketFormat;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.UnknownBCPGKey;
import org.bouncycastle.bcpg.sig.KeyExpirationTime;
import org.bouncycastle.util.test.SimpleTest;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Date;

public class TimeEncodingTest
        extends SimpleTest
{
    @Override
    public String getName()
    {
        return "UtilsTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        testRoundtrippingLargeUnsignedInt();
        testKeyWithLargeCreationTime();
    }

    private void testRoundtrippingLargeUnsignedInt()
    {
        // Integer.MAX_VALUE < large < 0xffffffff
        long large = 2523592696L; // fits a 32-bit *unsigned* int, but overflows signed int
        // KeyExpirationTime packs the time into 4 octets
        KeyExpirationTime kexp = new KeyExpirationTime(false, large);
        // getTime() parses the time from 4 octets
        isEquals("Roundtripped unsigned int mismatches before packet parser pass", large, kexp.getTime());

        // To be safe, do an additional packet encode/decode roundtrip
        KeyExpirationTime pKexp = new KeyExpirationTime(kexp.isCritical(), kexp.isLongLength(), kexp.getData());
        isEquals("Roundtripped unsigned int mismatches after packet parser pass", large, pKexp.getTime());
    }

    private void testKeyWithLargeCreationTime()
            throws IOException
    {
        long maxSeconds = 0xFFFFFFFEL; // Fits 32 unsigned int, but not signed int
        Date maxPGPDate = new Date(maxSeconds * 1000);
        UnknownBCPGKey k = new UnknownBCPGKey(1, new byte[]{1}); // dummy
        PublicKeyPacket p = new PublicKeyPacket(PublicKeyPacket.VERSION_6, 99, maxPGPDate, k);
        isEquals("Key creation time mismatches before encoding", maxPGPDate, p.getTime());

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        BCPGOutputStream pOut = new BCPGOutputStream(bOut, PacketFormat.CURRENT);
        p.encode(pOut);
        pOut.close();
        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        BCPGInputStream pIn = new BCPGInputStream(bIn);
        PublicKeyPacket parsed = (PublicKeyPacket) pIn.readPacket();
        isEquals("Key creation time mismatches after encoding", maxPGPDate, parsed.getTime());
    }

    public static void main(String[] args)
    {
        runTest(new TimeEncodingTest());
    }
}
