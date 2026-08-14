package org.bouncycastle.bcpg.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;

/**
 * ArmoredInputStream parses the armor headers as it is constructed, so what it accumulates there is
 * reachable by merely wrapping an untrusted stream. Neither the length of a header line nor the
 * number of them was bounded: a "header line" that never reaches a terminator, and short header
 * lines that never stop arriving, each exhausted the heap inside the constructor. Both are now
 * capped, by org.bouncycastle.openpgp.max_armor_header_length and
 * org.bouncycastle.openpgp.max_armor_headers.
 */
public class ArmoredInputStreamHeaderLimitTest
    extends AbstractPacketTest
{
    public String getName()
    {
        return "ArmoredInputStreamHeaderLimitTest";
    }

    public void performTest()
        throws Exception
    {
        overLongHeaderLineIsRejected();
        tooManyHeadersAreRejected();
        configuredLimitsAreHonoured();
        ordinaryArmorStillRoundTrips();
    }

    private void overLongHeaderLineIsRejected()
        throws IOException
    {
        StringBuffer armor = new StringBuffer("-----BEGIN PGP MESSAGE-----\nComment: ");
        for (int i = 0; i != 5000; i++)
        {
            armor.append('A');
        }
        armor.append("\n\n");

        try
        {
            new ArmoredInputStream(new ByteArrayInputStream(Strings.toByteArray(armor.toString())));
            fail("over-long armor header line accepted");
        }
        catch (IOException e)
        {
            isEquals("armor header line exceeds 4096 bytes (see org.bouncycastle.openpgp.max_armor_header_length)",
                e.getMessage());
        }
    }

    private void tooManyHeadersAreRejected()
        throws IOException
    {
        StringBuffer armor = new StringBuffer("-----BEGIN PGP MESSAGE-----\n");
        for (int i = 0; i != 100; i++)
        {
            armor.append("Comment: x\n");
        }
        armor.append("\n");

        try
        {
            new ArmoredInputStream(new ByteArrayInputStream(Strings.toByteArray(armor.toString())));
            fail("unbounded run of armor headers accepted");
        }
        catch (IOException e)
        {
            isEquals("more than 64 armor headers (see org.bouncycastle.openpgp.max_armor_headers)", e.getMessage());
        }
    }

    /**
     * The limits are configurable in both directions, and a value that cannot be a limit leaves the
     * default in place rather than removing it.
     */
    private void configuredLimitsAreHonoured()
        throws IOException
    {
        StringBuffer armor = new StringBuffer("-----BEGIN PGP MESSAGE-----\n");
        for (int i = 0; i != 20; i++)
        {
            armor.append("Comment: x\n");
        }
        armor.append("\n");

        byte[] armored = Strings.toByteArray(armor.toString());

        // within the default limit of 64
        new ArmoredInputStream(new ByteArrayInputStream(armored));

        System.setProperty(Properties.OPENPGP_MAX_ARMOR_HEADERS, "8");
        try
        {
            new ArmoredInputStream(new ByteArrayInputStream(armored));
            fail("configured armor header limit ignored");
        }
        catch (IOException e)
        {
            isEquals("more than 8 armor headers (see org.bouncycastle.openpgp.max_armor_headers)", e.getMessage());
        }
        finally
        {
            System.getProperties().remove(Properties.OPENPGP_MAX_ARMOR_HEADERS);
        }

        System.setProperty(Properties.OPENPGP_MAX_ARMOR_HEADERS, "0");
        try
        {
            // "0" cannot be a limit, so the default applies and this is accepted
            new ArmoredInputStream(new ByteArrayInputStream(armored));
        }
        finally
        {
            System.getProperties().remove(Properties.OPENPGP_MAX_ARMOR_HEADERS);
        }
    }

    private void ordinaryArmorStillRoundTrips()
        throws IOException
    {
        byte[] data = Strings.toByteArray("Hello, World!");

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ArmoredOutputStream aOut = ArmoredOutputStream.builder()
            .setVersion("BCPG")
            .addComment("a comment")
            .build(bOut);

        aOut.write(data);
        aOut.close();

        ArmoredInputStream aIn = new ArmoredInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        isTrue("armored round trip", Arrays.areEqual(data, Streams.readAll(aIn)));

        aIn.close();
    }

    public static void main(String[] args)
    {
        runTest(new ArmoredInputStreamHeaderLimitTest());
    }
}
