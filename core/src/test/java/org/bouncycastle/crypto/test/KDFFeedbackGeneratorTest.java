package org.bouncycastle.crypto.test;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.Charset;

import org.bouncycastle.crypto.test.cavp.CAVPReader;
import org.bouncycastle.crypto.test.cavp.KDFFeedbackCounterTests;
import org.bouncycastle.crypto.test.cavp.KDFFeedbackNoCounterTests;
import org.bouncycastle.util.test.SimpleTest;

public class KDFFeedbackGeneratorTest
    extends SimpleTest
{
    public String getName()
    {
        return this.getClass().getSimpleName();
    }

    public void performTest()
        throws Exception
    {
        testFeedbackCounter();
        testFeedbackNoCounter();
    }

    private static void testFeedbackCounter()
    {

        CAVPReader cavpReader = new CAVPReader(new KDFFeedbackCounterTests());

        final InputStream stream = CAVPReader.class.getResourceAsStream("KDFFeedbackCounter_gen.rsp");
        final Reader reader = new InputStreamReader(stream, Charset.forName("UTF-8"));
        cavpReader.setInput("KDFFeedbackCounter", reader);

        try
        {
            cavpReader.readAll();
        }
        catch (IOException e)
        {
            throw new IllegalStateException("Something is rotten in the state of Denmark ", e);
        }
    }

    private static void testFeedbackNoCounter()
    {

        CAVPReader cavpReader = new CAVPReader(new KDFFeedbackNoCounterTests());

        final InputStream stream = CAVPReader.class.getResourceAsStream("KDFFeedbackNoCounter_gen.rsp");
        final Reader reader = new InputStreamReader(stream, Charset.forName("UTF-8"));
        cavpReader.setInput("KDFFeedbackNoCounter", reader);

        try
        {
            cavpReader.readAll();
        }
        catch (IOException e)
        {
            throw new IllegalStateException("Something is rotten in the state of Denmark", e);
        }
    }

    public static void main(String[] args)
    {
        runTest(new KDFDoublePipelineIteratorGeneratorTest());
    }
}
