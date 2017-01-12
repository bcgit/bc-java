package org.bouncycastle.crypto.tls;

import java.io.OutputStream;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterOutputStream;

public class TlsDeflateCompression implements TlsCompression {

    private final Deflater deflater = new Deflater(Deflater.BEST_SPEED);
    private final Inflater inflater = new Inflater();

    @Override
    public OutputStream compress(OutputStream output) {
        return new DeflaterOutputStream(output, deflater);
    }

    @Override
    public OutputStream decompress(OutputStream output) {
        return new InflaterOutputStream(output, inflater);
    }

}
