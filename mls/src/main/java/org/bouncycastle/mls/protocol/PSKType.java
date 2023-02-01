package org.bouncycastle.mls.protocol;

import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSOutputStream;

import java.io.IOException;

public enum PSKType implements MLSInputStream.Readable, MLSOutputStream.Writable {
    EXTERNAL((byte) 1),
    RESUMPTION((byte) 2);

    final byte value;

    PSKType(byte value) {
        this.value = value;
    }

    @SuppressWarnings("unused")
    PSKType(MLSInputStream stream) throws IOException {
        this.value = (byte) stream.read(byte.class);
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException {
        stream.write(value);
    }
}
