package org.bouncycastle.mls.codec;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class MLSOutputStream {
    public interface Writable {
        void writeTo(MLSOutputStream stream) throws IOException;
    }

    final ByteArrayOutputStream stream;

    public MLSOutputStream() {
        stream = new ByteArrayOutputStream();
    }

    public static byte[] encode(Object val) throws IOException {
        MLSOutputStream stream = new MLSOutputStream();
        stream.write(val);
        return stream.toByteArray();
    }

    public void write(Object val) throws IOException {
        Class<?> valClass = val.getClass();
        if (valClass == Boolean.class) {
            writeBoolean((boolean) val);
            return;
        } else if (valClass == Byte.class) {
            writeInt((byte)val, 1);
            return;
        } else if (valClass == Short.class) {
            writeInt((short)val, 2);
            return;
        } else if (valClass == Integer.class) {
            writeInt((int)val, 4);
            return;
        } else if (valClass == Long.class) {
            writeInt((long)val, 8);
            return;
        } else if (Writable.class.isAssignableFrom(valClass)) {
            ((Writable) val).writeTo(this);
            return;
        }

        throw new IllegalArgumentException("Target type cannot be encoded");
    }

    public byte[] toByteArray() {
        return stream.toByteArray();
    }

    void writeBoolean(boolean val) {
        writeInt((val) ? 1 : 0, 1);
    }

    private void writeInt(long val, int len) {
        for (int i = 0; i < len; i++) {
            byte b = (byte)(val >> (8 * (len - i - 1)));
            stream.write(b);
        }
    }

    public void writeOptional(Object val) throws IOException {
        writeBoolean(val != null);
        if (val != null) {
            write(val);
        }
    }

    public <T> void writeArray(T[] val) throws IOException {
        for (T x : val) {
            write(x);
        }
    }

    public void writeOpaque(byte[] val) throws IOException {
        write(new Varint(val.length));
        stream.write(val);
    }

    public <T> void writeList(Iterable<T> val) throws IOException {
        // Pre-encode content
        MLSOutputStream content = new MLSOutputStream();
        for (T x : val) {
            content.write(x);
        }

        // Write the header, then copy over the content
        write(new Varint(content.stream.size()));
        content.stream.writeTo(stream);
    }
}
