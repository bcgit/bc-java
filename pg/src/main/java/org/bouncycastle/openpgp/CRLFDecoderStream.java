package org.bouncycastle.openpgp;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Deque;

/**
 * InputStream that transforms "\r\n" line endings into the local machine's line ending format.
 * On Windows machines that will be "\r\n" (data is unchanged), while on unixoide machines, line endings will be
 * decoded to "\n".
 */
public class CRLFDecoderStream extends FilterInputStream {

    private final byte[] lineSep;
    private final Deque<Integer> buffer = new ArrayDeque<>();

    public CRLFDecoderStream(InputStream in) {
        this(in, System.lineSeparator());
    }

    public CRLFDecoderStream(InputStream in, String lineSep) {
        super(in);
        this.lineSep = lineSep.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public int read(byte[] b) throws IOException {
        return read(b, 0, b.length);
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if ((off | len | b.length - (len + off) | off + len) < 0) {
            throw new IndexOutOfBoundsException();
        }

        int read = 0;
        for (int i = 0; i < len; i++) {
            int r = read();
            if (r == -1) {
                break;
            }

            b[off + i] = (byte) r;
            read++;
        }
        return read == 0 ? -1 : read;
    }

    @Override
    public int read() throws IOException {
        int b = buffer.isEmpty() ? super.read() : buffer.pop();

        if (b == '\r') {
            b = super.read();
            if (b == '\n') {
                for (byte s : lineSep) {
                    buffer.addLast((int) s);
                }
                return buffer.pop();
            } else {
                buffer.addLast(b);
                return '\r';
            }
        } else {
            return b;
        }
    }
}
