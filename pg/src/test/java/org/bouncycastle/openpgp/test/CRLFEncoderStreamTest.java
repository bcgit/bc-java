package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.openpgp.CRLFEncoderStream;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.test.SimpleTest;

public class CRLFEncoderStreamTest extends SimpleTest {

    public static void main(String[] args) throws Exception {
        new CRLFEncoderStreamTest().performTest();
    }

    @Override
    public String getName() {
        return CRLFEncoderStreamTest.class.getSimpleName();
    }

    @Override
    public void performTest() throws Exception {
        assertEncodingEquals("Foo\r\nBar", "Foo\r\nBar");
        assertEncodingEquals("Foo\r\r\nBar", "Foo\r\r\nBar");
        assertEncodingEquals("Foo\nBar", "Foo\r\nBar");
        assertEncodingEquals("Foo\n\nBar", "Foo\r\n\r\nBar");
    }

    private void assertEncodingEquals(String input, String expectedCRLFEncoding) throws IOException {
        assertEncodingEquals(input.getBytes(StandardCharsets.UTF_8), expectedCRLFEncoding.getBytes(StandardCharsets.UTF_8));
    }

    private void assertEncodingEquals(byte[] input, byte[] expectedCRLFEncoding) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        CRLFEncoderStream crlf = new CRLFEncoderStream(out);

        Streams.pipeAll(new ByteArrayInputStream(input), crlf);

        isTrue(areEqual(expectedCRLFEncoding, out.toByteArray()));
    }
}
