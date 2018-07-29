package org.bouncycastle.mime.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import junit.framework.TestCase;
import org.bouncycastle.mime.BoundaryLimitedInputStream;
import org.bouncycastle.util.io.Streams;

public class TestBoundaryLimitedInputStream
    extends TestCase
{
    public void testBoundaryAfterCRLF()
        throws Exception
    {
        String data = "The cat sat on the mat\r\n" +
            "then it went to sleep";


        ByteArrayInputStream bin = new ByteArrayInputStream((data + "\r\n--banana").getBytes());

        BoundaryLimitedInputStream blin = new BoundaryLimitedInputStream(bin, "banana");

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        Streams.pipeAll(blin, bos);

        TestCase.assertEquals(data, bos.toString());
    }

    public void testBoundaryAfterCRLFTrailingLineInContent()
        throws Exception
    {
        String data = "The cat sat on the mat\r\n" +
            "then it went to sleep\r\n";


        ByteArrayInputStream bin = new ByteArrayInputStream((data + "\r\n--banana").getBytes());

        BoundaryLimitedInputStream blin = new BoundaryLimitedInputStream(bin, "banana");

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        Streams.pipeAll(blin, bos);

        TestCase.assertEquals(data, bos.toString());
    }

    public void testBoundaryAfterLF()
        throws Exception
    {
        String data = "The cat sat on the mat\r\n" +
            "then it went to sleep";


        ByteArrayInputStream bin = new ByteArrayInputStream((data + "\n--banana").getBytes());

        BoundaryLimitedInputStream blin = new BoundaryLimitedInputStream(bin, "banana");

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        Streams.pipeAll(blin, bos);

        TestCase.assertEquals(data, bos.toString());
    }

    public void testBoundaryAfterLFTrailingLine()
        throws Exception
    {
        String data = "The cat sat on the mat\r\n" +
            "then it went to sleep\n";


        ByteArrayInputStream bin = new ByteArrayInputStream((data + "\n--banana").getBytes());

        BoundaryLimitedInputStream blin = new BoundaryLimitedInputStream(bin,"banana");

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        Streams.pipeAll(blin, bos);

        TestCase.assertEquals(data, bos.toString());
    }
}
