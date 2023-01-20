package org.bouncycastle.mls.codec;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.security.InvalidParameterException;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;

public class Decoder {
    static class SliceableStream extends ByteArrayInputStream {
        public SliceableStream(byte[] buf) {
            super(buf);
        }

        public SliceableStream(byte[] buf, int pos, int size) {
            super(buf, pos, size);
        }

        byte[] readAll(int size) throws IOException {
            byte[] data = new byte[size];
            int length = super.read(data);
            if (length != data.length) {
                throw new IOException("Attempt to read beyond end of buffer");
            }
            return data;
        }

        byte peek() throws IOException {
            mark(1);
            int val = read();
            reset();
            if (val == -1) {
                throw new IOException("Attempt to peek past end of buffer");
            }
            return (byte) val;
        }

        SliceableStream slice(int size) throws IOException {
            if (size > available()) {
                throw new IOException("Attempt to read past end of buffer");
            }

            return new SliceableStream(buf, pos, size);
        }
    }

    SliceableStream stream;

    public Decoder(byte[] data) {
        stream = new SliceableStream(data);
    }

    Decoder(SliceableStream streamIn) { stream = streamIn; }

    public Object decode(Class<?> targetClass) throws IOException, InstantiationException, IllegalAccessException, InvocationTargetException, NoSuchMethodException {
        return decode(targetClass, null);
    }

    public Object decode(Class<?> targetClass, MLSField opts) throws IOException, InstantiationException, IllegalAccessException, InvocationTargetException, NoSuchMethodException {
        if (opts != null && opts.optional()) {
            int flag = stream.read();
            switch (flag) {
                case 0:
                    return null;
                case 1:
                    break;
                default:
                    throw new IOException("Invalid optional");
            }
        }

        if (targetClass == Boolean.class) {
            return decodeBoolean();
        } else if (targetClass == Byte.class || targetClass == byte.class) {
            return (byte) decodeInt(1);
        } else if (targetClass == Short.class || targetClass == short.class) {
            return (short) decodeInt(2);
        } else if (targetClass == Integer.class || targetClass == int.class) {
            return (int) decodeInt(4);
        } else if (targetClass == Long.class || targetClass == long.class) {
            return decodeInt(8);
        } else if (targetClass.isArray()) {
            return decodeArray(targetClass, opts);
        } else if (List.class.isAssignableFrom(targetClass)) {
            return decodeList(targetClass, opts);
        }

        return decodeStruct(targetClass);
    }

    boolean decodeBoolean() throws IOException {
        switch ((byte) decodeInt(1)) {
            case 0: return false;
            case 1: return true;
            default: throw new IOException("Invalid boolean value");
        }
    }

    long decodeInt(byte[] data) {
        long out = 0;
        for (byte b : data) {
            out <<= 8;
            out |= (b & 0xff);
        }
        return out;
    }

    long decodeInt(int size) throws IOException {
        return decodeInt(stream.readAll(size));
    }

    Object decodeArray(Class<?> targetClass, MLSField opts) throws IOException, InstantiationException, IllegalAccessException, InvocationTargetException, NoSuchMethodException {
        if (opts == null) {
            throw new IllegalArgumentException("Array cannot be decoded without length");
        }

        int length = opts.length();
        Class<?> elemClass = targetClass.getComponentType();

        // If this is a byte array, read directly
        if (elemClass == Byte.class) {
            return stream.readAll(length);
        }

        // Otherwise, recursively decode entries
        Object val = Array.newInstance(elemClass, length);
        for (int i = 0; i < length; i++) {
            Object elem = decode(elemClass);
            Array.set(val, i, elem);
        }
        return val;
    }

    private int decodeVarint() throws IOException {
        int logSize = stream.peek() >> Varint.HEADER_OFFSET;
        int size = 1 << logSize;
        long unset;
        switch (size) {
            case 1:
                unset = Varint.HEADER_1;
                break;
            case 2:
                unset = Varint.HEADER_2;
                break;
            case 4:
                unset = Varint.HEADER_4;
                break;
            default:
                throw new IOException("Invalid varint header");
        }

        return (int)(decodeInt(size) ^ unset);
    }

    Object decodeList(Class<?> targetClass, MLSField opts) throws IOException, InstantiationException, IllegalAccessException, NoSuchMethodException, InvocationTargetException {
        // Prepare to read into a vector
        if (opts == null) {
            throw new InvalidParameterException("Lists must specify their element type");
        }

        Class<?> elemClass = opts.element();

        @SuppressWarnings("rawtypes")
        List vec = (List) targetClass.getDeclaredConstructor().newInstance();

        // Decode the vector length, then read elements
        int size = decodeVarint();
        Decoder dec = new Decoder(stream.slice(size));
        while (dec.stream.available() > 0) {
            Object elem = dec.decode(elemClass);
            vec.add(elem);
        }

        return vec;
    }

    Object decodeStruct(Class<?> targetClass) throws InstantiationException, IllegalAccessException, IOException, NoSuchMethodException, InvocationTargetException {
        // Objects to be read with this method must be POJOs, in the sense that
        //   (a) they must be default-constructible
        //   (b) all fields set by reading must be public

        // Create a new object into which values will be filled
        Object val = targetClass.getDeclaredConstructor().newInstance();

        // Read the fields in order
        Field[] fields = Arrays.stream(targetClass.getDeclaredFields())
                .filter(f -> f.getAnnotation(MLSField.class) != null)
                .sorted(Comparator.comparingInt(f-> f.getAnnotation(MLSField.class).order()))
                .toArray(Field[]::new);
        for (Field f : fields) {
            Object fieldVal = decode(f.getType(), f.getAnnotation(MLSField.class));
            f.set(val, fieldVal);
        }

        return val;
    }
}
