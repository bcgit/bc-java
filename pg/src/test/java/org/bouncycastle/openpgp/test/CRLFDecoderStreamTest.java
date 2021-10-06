package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.openpgp.CRLFDecoderStream;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.test.SimpleTest;

public class CRLFDecoderStreamTest extends SimpleTest {

    public static void main(String[] args) throws Exception {
        new CRLFDecoderStreamTest().performTest();
    }

    @Override
    public String getName() {
        return CRLFDecoderStreamTest.class.getSimpleName();
    }

    @Override
    public void performTest() throws Exception {
        testCRLFtoCRLF();
        testCRLFtoLF();
    }

    private void testCRLFtoCRLF() throws IOException {
        assertDecodingEquals("Foo\r\nBar", "\r\n", "Foo\r\nBar");
        assertDecodingEquals("Foo\nBar\r\n", "\r\n", "Foo\nBar\r\n");
    }

    private void testCRLFtoLF() throws IOException {
        assertDecodingEquals("Foo\r\nBar", "\n", "Foo\nBar");
        assertDecodingEquals( "Foo\rx\r\r\nBar", "\n", "Foo\rx\r\nBar");
        assertDecodingEquals("Foo\r\nBar\r\n", "\n", "Foo\nBar\n");
    }

    private void assertDecodingEquals(String crlfEncoded, String localLineSeparator, String expected) throws IOException {
        assertDecodingEquals(crlfEncoded.getBytes(StandardCharsets.UTF_8), localLineSeparator, expected.getBytes(StandardCharsets.UTF_8));
    }

    private void assertDecodingEquals(byte[] crlfEncoded, String localLineSeparator, byte[] expected) throws IOException {
        ByteArrayInputStream base = new ByteArrayInputStream(crlfEncoded);
        CRLFDecoderStream crlfDecoder = new CRLFDecoderStream(base, localLineSeparator);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(crlfDecoder, out);

        byte[] after = out.toByteArray();
        isTrue(areEqual(expected, after));
    }
}
