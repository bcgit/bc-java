package org.bouncycastle.est.test;

import java.io.ByteArrayInputStream;

import junit.framework.TestCase;
import org.bouncycastle.est.CTEChunkedInputStream;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;

public class TestChunkedInputStream
    extends TestCase
{

    public void testRead()
        throws Exception
    {
        String body = "4\r\n" +
            "Wiki\r\n" +
            "6\r\n" +
            "pedia \r\n" +
            "E\r\n" +
            "in \r\n" +
            "\r\n" +
            "chunks.\r\n" +
            "0\r\n" +
            "\r\n";

        CTEChunkedInputStream inputStream = new CTEChunkedInputStream(new ByteArrayInputStream(body.getBytes()));
        String result = Strings.fromByteArray(Streams.readAll(inputStream));
        TestCase.assertEquals("Wikipedia in \r\n\r\n" +
            "chunks.", result);

        TestCase.assertEquals(-1,inputStream.read());

    }


    public void testEmpty() throws Exception {
        CTEChunkedInputStream inputStream = new CTEChunkedInputStream(new ByteArrayInputStream(new byte[0]));
        TestCase.assertEquals(-1,inputStream.read());
    }



}
