package org.bouncycastle.openpgp;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * OutputStream that encodes line endings as "\r\n".
 */
public class CRLFEncoderStream extends FilterOutputStream {

    private byte lastB;

    public CRLFEncoderStream(OutputStream out) {
        super(out);
    }

    @Override
    public void write(int b) throws IOException {
        if (b == '\n' && lastB != '\r') {
            super.write('\r');
        }
        lastB = (byte) b;
        super.write(b);
    }
}
