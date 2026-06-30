package org.bouncycastle.bcpg.test;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import org.bouncycastle.bcpg.MalformedPacketException;
import org.bouncycastle.bcpg.UserAttributeSubpacketInputStream;

/**
 * Regression test for the unbounded user-attribute subpacket allocation: a crafted 4-octet length
 * header must be rejected against the absolute MAX_SUBPACKET_LEN cap before any body buffer is
 * allocated, rather than relying on the StreamUtil.findLimit() hint (which is ~heap-sized for the
 * non-seekable streams used during packet parsing).
 */
public class UserAttributeSubpacketInputStreamTest
    extends AbstractPacketTest
{
    public String getName()
    {
        return "UserAttributeSubpacketInputStreamTest";
    }

    public void performTest()
        throws Exception
    {
        // A subpacket header declaring a 3 MiB body via the 4-octet length form, with no body.
        int claimed = 3 * 1024 * 1024;
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        bOut.write(0xFF);
        bOut.write((claimed >>> 24) & 0xFF);
        bOut.write((claimed >>> 16) & 0xFF);
        bOut.write((claimed >>> 8) & 0xFF);
        bOut.write(claimed & 0xFF);
        bOut.write(0x01); // subpacket type octet
        byte[] crafted = bOut.toByteArray();

        // BufferedInputStream is neither a ByteArrayInputStream nor a FileInputStream, so findLimit
        // returns ~Integer.MAX_VALUE -- the same toothless limit the BCPGInputStream parse path sees.
        UserAttributeSubpacketInputStream sIn = new UserAttributeSubpacketInputStream(
            new BufferedInputStream(new ByteArrayInputStream(crafted)));

        try
        {
            sIn.readPacket();
            fail("oversized user attribute subpacket length accepted");
        }
        catch (MalformedPacketException e)
        {
            isTrue("unexpected message: " + e.getMessage(),
                e.getMessage().indexOf("exceeds max user attribute subpacket length") >= 0);
        }
    }

    public static void main(String[] args)
    {
        runTest(new UserAttributeSubpacketInputStreamTest());
    }
}
