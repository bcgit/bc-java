package org.bouncycastle.asn1.test;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;

public class ParsingTest
    extends SimpleTest
{
     String[] streams = {
        "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"
     };

    public String getName()
    {
        return "ParsingTest";
    }

    public void performTest()
        throws Exception
    {
        inputStreamTest();
        parserTest();
    }

    private void parserTest()
    {
        for (int i = 0; i != streams.length; i++)
        {
            ASN1StreamParser aIn = new ASN1StreamParser(Base64.decode(streams[i]));

            try
            {
                Object obj;

                while ((obj = aIn.readObject()) != null)
                {

                }

                fail("bad stream parsed successfully!");
            }
            catch (IOException e)
            {
                // ignore
            }
        }
    }

    private void inputStreamTest()
    {
        for (int i = 0; i != streams.length; i++)
        {
            ASN1InputStream aIn = new ASN1InputStream(Base64.decode(streams[i]));

            try
            {
                Object obj;

                while ((obj = aIn.readObject()) != null)
                {

                }

                fail("bad stream parsed successfully!");
            }
            catch (IOException e)
            {
                // ignore
            }
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new ParsingTest());
    }
}
