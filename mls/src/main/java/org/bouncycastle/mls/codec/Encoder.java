package org.bouncycastle.mls.codec;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;

public class Encoder {
    final ByteArrayOutputStream stream;

    public Encoder() {
        stream = new ByteArrayOutputStream();
    }

    public void encode(Object val) throws IOException, IllegalAccessException {
        encode(val, null);
    }

    private void encode(Object val, MLSField opts) throws IOException, IllegalAccessException {
        if (opts != null && opts.optional()) {
            if (val == null) {
                // Null optional value encodes as just 0x00
                stream.write(0x00);
                return;
            } else {
                // Present optional value encodes as 0x01 followed by the real encoding
                stream.write(0x01);
            }
        } else if (val == null) {
            // Null values can only be provided in optional fields
            throw new NullPointerException("Null value outside of an optional field");
        }

        Class<?> valClass = val.getClass();
        if (valClass == Boolean.class) {
            encodeInt(((boolean) val) ? 1 : 0, 1);
            return;
        } else if (valClass == Byte.class) {
            encodeInt((byte)val, 1);
            return;
        } else if (valClass == Short.class) {
            encodeInt((short)val, 2);
            return;
        } else if (valClass == Integer.class) {
            encodeInt((int)val, 4);
            return;
        } else if (valClass == Long.class) {
            encodeInt((long)val, 8);
            return;
        } else if (valClass.isArray()) {
            encodeArray(val, opts);
            return;
        } else if (List.class.isAssignableFrom(valClass)) {
            encodeList((List<?>) val);
            return;
        }

        // If all else fails, attempt to encode as a struct
        encodeStruct(val);
    }

    public byte[] toByteArray() {
        return stream.toByteArray();
    }

    private void encodeInt(long val, int len) {
        for (int i = 0; i < len; i++) {
            byte b = (byte)(val >> (8 * (len - i - 1)));
            stream.write(b);
        }
    }

    private void encodeArray(Object val, MLSField opts) throws IOException, IllegalAccessException {
        int length = Array.getLength(val);
        if (opts != null && opts.length() != length) {
            throw new IllegalArgumentException("Array does not have correct length");
        }

        // If this is a byte array, write directly
        if (val.getClass().getComponentType() == Byte.class) {
            stream.write((byte[]) val);
            return;
        }

        // Otherwise, recursively encode entries
        for (int i = 0; i < length; i++) {
            encode(Array.get(val, i));
        }
    }

    private void encodeVarint(long val) throws IOException {
        if (val <= Varint.MAX_1) {
            encodeInt(Varint.HEADER_1 | val, 1);
        } else if (val <= Varint.MAX_2) {
            encodeInt(Varint.HEADER_2 | val, 2);
        } else if (val <= Varint.MAX_4) {
            encodeInt(Varint.HEADER_4 | val, 4);
        } else {
            throw new IOException("Varint is too big to encode");
        }
    }

    private <T> void encodeList(List<T> val) throws IOException, IllegalAccessException {
        // Pre-encode content
        Encoder content = new Encoder();
        for (T x : val) {
            content.encode(x);
        }

        // Write the header, then copy over the content
        encodeVarint(content.stream.size());
        content.stream.writeTo(stream);
    }

    private void encodeStruct(Object val) throws IllegalAccessException, IOException {
        // Find and sort encodable fields
        Field[] fields = Arrays.stream(val.getClass().getDeclaredFields())
                .filter(f -> f.getAnnotation(MLSField.class) != null)
                .sorted(Comparator.comparingInt(f-> f.getAnnotation(MLSField.class).order()))
                .toArray(Field[]::new);

        // Encode the field values
        for (Field f : fields) {
            encode(f.get(val), f.getAnnotation(MLSField.class));
        }
    }
}
