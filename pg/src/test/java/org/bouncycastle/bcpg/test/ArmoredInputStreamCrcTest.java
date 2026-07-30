package org.bouncycastle.bcpg.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;

/**
 * On reaching the armor checksum line ArmoredInputStream.read() sets crcFound and then returns
 * read(), i.e. calls itself. The running CRC is not reset between lines, so the same four characters
 * keep matching, and each match cost another stack frame: repeating "=twTO" - base64 of the CRC-24
 * initial value, so no data bytes are needed at all - drove read() thousands of frames deep and threw
 * StackOverflowError, which is an Error and so escapes the catch (IOException) a caller puts around
 * PGP parsing. RFC 9580 sec. 6.2 puts the checksum once, immediately before the armor tail, so a
 * second one is now rejected and the self-call cannot repeat.
 */
public class ArmoredInputStreamCrcTest
    extends AbstractPacketTest
{
    public String getName()
    {
        return "ArmoredInputStreamCrcTest";
    }

    public void performTest()
        throws Exception
    {
        repeatedChecksumLineIsRejected();
        repeatedChecksumAfterRealBodyIsRejected();
        wellFormedArmorStillRoundTrips();
    }

    private static byte[] repeatedChecksumArmor(int lines)
    {
        StringBuffer sb = new StringBuffer();

        // no headers and no data at all: the CRC-24 of nothing is its initial value, so every line
        // matches. A CRLF-terminated header block instead trips the armor header parse first, which
        // is an earlier rejection and would not reach the checksum branch being tested here.
        sb.append("-----BEGIN PGP MESSAGE-----\n\n\n");
        for (int i = 0; i != lines; i++)
        {
            sb.append("=twTO\n");
        }
        sb.append("-----END PGP MESSAGE-----\n");

        return Strings.toByteArray(sb.toString());
    }

    private void drain(byte[] armor)
        throws IOException
    {
        ArmoredInputStream aIn = new ArmoredInputStream(new ByteArrayInputStream(armor));
        try
        {
            Streams.drain(aIn);
        }
        finally
        {
            aIn.close();
        }
    }

    /**
     * 60,000 checksum lines is ~360KB of plain ASCII, which used to be enough to exhaust a default
     * thread stack. The failure to look for is a StackOverflowError, not the message.
     */
    private void repeatedChecksumLineIsRejected()
        throws Exception
    {
        byte[] armor = repeatedChecksumArmor(60000);

        try
        {
            drain(armor);
            fail("repeated checksum lines accepted");
        }
        catch (StackOverflowError e)
        {
            fail("read() recursed to StackOverflowError");
        }
        catch (IOException e)
        {
            isTrue(e.getMessage(), e.getMessage().indexOf("crc") >= 0);
        }
    }

    /** The same trailer appended to a real armored body, which is how it would actually arrive. */
    private void repeatedChecksumAfterRealBodyIsRejected()
        throws Exception
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ArmoredOutputStream aOut = new ArmoredOutputStream(bOut);
        aOut.write(Strings.toByteArray("the quick brown fox"));
        aOut.close();

        String armored = Strings.fromByteArray(bOut.toByteArray());

        // keep everything up to and including the real checksum line, then repeat one
        int tail = armored.indexOf("-----END");
        StringBuffer sb = new StringBuffer(armored.substring(0, tail));
        for (int i = 0; i != 20000; i++)
        {
            sb.append("=twTO\n");
        }
        sb.append(armored.substring(tail));

        try
        {
            drain(Strings.toByteArray(sb.toString()));
            fail("repeated checksum lines after a body accepted");
        }
        catch (StackOverflowError e)
        {
            fail("read() recursed to StackOverflowError");
        }
        catch (IOException e)
        {
            isTrue(e.getMessage(), e.getMessage().indexOf("crc") >= 0);
        }
    }

    /** The compatibility assertion: one checksum line, as every real message carries. */
    private void wellFormedArmorStillRoundTrips()
        throws Exception
    {
        byte[] data = Strings.toByteArray("the quick brown fox jumps over the lazy dog");

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ArmoredOutputStream aOut = new ArmoredOutputStream(bOut);
        aOut.write(data);
        aOut.close();

        ArmoredInputStream aIn = new ArmoredInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        byte[] recovered = Streams.readAll(aIn);
        aIn.close();

        isTrue("armored round trip", Arrays.areEqual(data, recovered));

        // Two messages back to back, which is what proves the rejection is per-message: the armor
        // tail clears crcFound, so the second message's checksum must not read as a repeat of the
        // first. Note ArmoredInputStream runs the two bodies together into one stream of content
        // rather than stopping at the first tail - that is long-standing behaviour, unchanged here,
        // and what matters is that both bodies come through instead of the second being refused.
        ByteArrayOutputStream twoOut = new ByteArrayOutputStream();
        twoOut.write(bOut.toByteArray());
        twoOut.write(bOut.toByteArray());

        ArmoredInputStream twoIn = new ArmoredInputStream(new ByteArrayInputStream(twoOut.toByteArray()));
        byte[] both = Streams.readAll(twoIn);
        twoIn.close();

        isTrue("two messages", Arrays.areEqual(Arrays.concatenate(data, data), both));
    }
}
