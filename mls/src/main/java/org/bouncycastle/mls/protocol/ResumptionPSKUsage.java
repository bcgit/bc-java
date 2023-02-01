package org.bouncycastle.mls.protocol;

import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSOutputStream;

import java.io.IOException;

public enum ResumptionPSKUsage implements MLSInputStream.Readable, MLSOutputStream.Writable {
    APPLICATION((byte) 1),
    REINIT((byte) 2),
    BRANCH((byte) 3);

    final byte value;

    ResumptionPSKUsage(byte value) {
        this.value = value;
    }

    @SuppressWarnings("unused")
    ResumptionPSKUsage(MLSInputStream stream) throws IOException {
        this.value = (byte) stream.read(byte.class);
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException {
        stream.write(value);
    }
}
