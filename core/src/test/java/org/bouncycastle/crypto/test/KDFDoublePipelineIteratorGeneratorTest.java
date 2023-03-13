package org.bouncycastle.crypto.test;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.Charset;

import org.bouncycastle.crypto.test.cavp.CAVPReader;
import org.bouncycastle.crypto.test.cavp.KDFDoublePipelineCounterTests;
import org.bouncycastle.crypto.test.cavp.KDFDoublePipelineIterationNoCounterTests;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.test.SimpleTest;

public class KDFDoublePipelineIteratorGeneratorTest
    extends SimpleTest
{
    public String getName()
    {
        return this.getClass().getSimpleName();
    }

    public void performTest()
        throws Exception
    {
        testDoublePipelineIterationCounter();
        testDoublePipelineIterationNoCounter();
    }

    private static void testDoublePipelineIterationCounter()
        throws FileNotFoundException
    {

        CAVPReader cavpReader = new CAVPReader(new KDFDoublePipelineCounterTests());

        final InputStream stream = TestResourceFinder.findTestResource("crypto/cavp", "KDFDblPipelineCounter_gen.rsp");
        final Reader reader = new InputStreamReader(stream, Charset.forName("UTF-8"));
        cavpReader.setInput("KDFDoublePipelineIterationCounter", reader);

        try
        {
            cavpReader.readAll();
        }
        catch (IOException e)
        {
            throw new IllegalStateException("Something is rotten in the state of Denmark", e);
        }
    }

    private static void testDoublePipelineIterationNoCounter()
        throws FileNotFoundException
    {

        CAVPReader cavpReader = new CAVPReader(new KDFDoublePipelineIterationNoCounterTests());

        final InputStream stream = TestResourceFinder.findTestResource("crypto/cavp", "KDFDblPipelineNoCounter_gen.rsp");
        final Reader reader = new InputStreamReader(stream, Charset.forName("UTF-8"));
        cavpReader.setInput("KDFDblPipelineIterationNoCounter", reader);

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
