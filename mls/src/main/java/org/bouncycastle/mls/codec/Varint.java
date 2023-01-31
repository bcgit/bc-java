package org.bouncycastle.mls.codec;

import java.io.IOException;

public class Varint implements MLSInputStream.Readable, MLSOutputStream.Writable {
    static final int HEADER_OFFSET = 6;
    static final int HEADER_1 = 0x00;
    static final int HEADER_2 = 0x4000;
    static final int HEADER_4 = 0x80000000;
    static final int MAX_1 = 0x3f;
    static final int MAX_2 = 0x3fff;
    static final int MAX_4 = 0x3fffffff;

    public final int value;

    public Varint(int value) {
        this.value = value;
    }

    @SuppressWarnings("unused")
    public Varint(MLSInputStream stream) throws IOException {
        int logSize = stream.peek() >> HEADER_OFFSET;
        int size = 1 << logSize;
        switch (size) {
            case 1:
                value = HEADER_1 ^ (int)(byte) stream.read(byte.class);
                break;
            case 2:
                value = HEADER_2 ^ (int)(short) stream.read(short.class);
                break;
            case 4:
                value = HEADER_4 ^ (int) stream.read(int.class);
                break;
            default:
                throw new IOException("Invalid varint header");
        }
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException {
        if (value <= MAX_1) {
            stream.write((byte)(HEADER_1 | value));
        } else if (value <= MAX_2) {
            stream.write((short)(HEADER_2 | value));
        } else if (value <= Varint.MAX_4) {
            stream.write(HEADER_4 | value);
        } else {
            throw new IOException("Varint is too big to encode");
        }
    }
}
