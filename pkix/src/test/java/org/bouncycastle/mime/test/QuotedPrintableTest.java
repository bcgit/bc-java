package org.bouncycastle.mime.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import junit.framework.TestCase;
import org.bouncycastle.mime.encoding.QuotedPrintableInputStream;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;

public class QuotedPrintableTest
    extends TestCase
{
    public void testQuotedPrintable()
        throws IOException
    {
        String qp = "J'interdis aux marchands de vanter trop leur marchandises. Car ils se font =\n" +
            "vite p=C3=A9dagogues et t'enseignent comme but ce qui n'est par essence qu'=\n" +
            "un moyen, et te trompant ainsi sur la route =C3=A0 suivre les voil=C3=A0 bi=\n" +
            "ent=C3=B4t qui te d=C3=A9gradent, car si leur musique est vulgaire ils te f=\n" +
            "abriquent pour te la vendre une =C3=A2me vulgaire."; // From wikipedia.

        QuotedPrintableInputStream qpd = new QuotedPrintableInputStream(new ByteArrayInputStream(Strings.toByteArray(qp)));

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        Streams.pipeAll(qpd, bos);

        TestCase.assertEquals("J'interdis aux marchands de vanter trop leur marchandises. Car ils se font vite pédagogues et t'enseignent comme but ce qui n'est par essence qu'un moyen, et te trompant ainsi sur la route à suivre les voilà bientôt qui te dégradent, car si leur musique est vulgaire ils te fabriquent pour te la vendre une âme vulgaire.", bos.toString());
    }

    public void testCRLFHandling()
        throws Exception
    {
        // Some client use CR others use CRLF.

        String qp = "The cat sat =\r\non the mat";
        String expected = "The cat sat on the mat";

        QuotedPrintableInputStream qpd = new QuotedPrintableInputStream(new ByteArrayInputStream(Strings.toByteArray(qp)));

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        Streams.pipeAll(qpd, bos);


        TestCase.assertEquals(expected, bos.toString());

    }

    public void testLFHandling()
        throws Exception
    {

        // Some client use CRLF others just use LF.

        String qp = "The cat sat =\non the mat";
        String expected = "The cat sat on the mat";

        QuotedPrintableInputStream qpd = new QuotedPrintableInputStream(new ByteArrayInputStream(Strings.toByteArray(qp)));

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        Streams.pipeAll(qpd, bos);

        TestCase.assertEquals(expected, bos.toString());
    }

    /**
     * No character after '='.
     *
     * @throws Exception
     */
    public void testInvalid_1()
        throws Exception
    {

        // Some client use CRLF others just use LF.

        String qp = "The cat sat =";


        QuotedPrintableInputStream qpd = new QuotedPrintableInputStream(new ByteArrayInputStream(Strings.toByteArray(qp)));

        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        try
        {
            Streams.pipeAll(qpd, bos);
            TestCase.fail("Must fail!");
        }
        catch (Throwable ioex)
        {
            TestCase.assertEquals("Quoted '=' at end of stream", ioex.getMessage());
        }
    }

    /**
     * Not hex digit on first character.
     *
     * @throws Exception
     */
    public void testInvalid_2()
        throws Exception
    {

        // Some client use CRLF others just use LF.

        String qp = "The cat sat =Z";

        QuotedPrintableInputStream qpd = new QuotedPrintableInputStream(new ByteArrayInputStream(Strings.toByteArray(qp)));
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        try
        {
            Streams.pipeAll(qpd, bos);
            TestCase.fail("Must fail!");
        }
        catch (Throwable ioex)
        {
            TestCase.assertEquals("Expecting '0123456789ABCDEF after quote that was not immediately followed by LF or CRLF", ioex.getMessage());
        }
    }

    /**
     * Not hex digit on second character.
     *
     * @throws Exception
     */
    public void testInvalid_3()
        throws Exception
    {

        // Some client use CRLF others just use LF.

        String qp = "The cat sat =AZ";

        QuotedPrintableInputStream qpd = new QuotedPrintableInputStream(new ByteArrayInputStream(Strings.toByteArray(qp)));

        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        try
        {
            Streams.pipeAll(qpd, bos);
            TestCase.fail("Must fail!");
        }
        catch (Throwable ioex)
        {
            TestCase.assertEquals("Expecting second '0123456789ABCDEF after quote that was not immediately followed by LF or CRLF", ioex.getMessage());
        }
    }
}
