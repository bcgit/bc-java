package org.bouncycastle.mls.codec;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.List;

public class MLSInputStream {
    public interface Readable {
        /*
        This interface is used as a marker, because Java interfaces cannot require
        the presence of specific constructors or static factory methods.  An attempt
        to read a Readable object will result in an attempt to find and invoke a
        constructor that takes MLSInputStream as an argument.

        You may want to apply @SuppressWarnings("unused") to this constructor, since
        the compiler won't pick up uses via this class.
         */
    } 
    
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

    public MLSInputStream(byte[] data) {
        stream = new SliceableStream(data);
    }

    MLSInputStream(SliceableStream stream) { this.stream = stream; }

    public static Object decode(byte[] data, Class<?> targetClass) throws IOException {
        MLSInputStream stream = new MLSInputStream(data);
        return stream.read(targetClass);
    }

    public Object read(Class<?> targetClass) throws IOException {
        if (targetClass == Boolean.class) {
            return readBoolean();
        } else if (targetClass == Byte.class || targetClass == byte.class) {
            return (byte) readInt(1);
        } else if (targetClass == Short.class || targetClass == short.class) {
            return (short) readInt(2);
        } else if (targetClass == Integer.class || targetClass == int.class) {
            return (int) readInt(4);
        } else if (targetClass == Long.class || targetClass == long.class) {
            return readInt(8);
        } else if (Readable.class.isAssignableFrom(targetClass)) {
            return readReadable(targetClass);
        }

        throw new IllegalArgumentException("Target type cannot be decoded");
    }

    byte peek() throws IOException {
        return stream.peek();
    }

    boolean readBoolean() throws IOException {
        switch ((byte) readInt(1)) {
            case 0: return false;
            case 1: return true;
            default: throw new IOException("Invalid boolean value");
        }
    }

    long readInt(byte[] data) {
        long out = 0;
        for (byte b : data) {
            out <<= 8;
            out |= (b & 0xff);
        }
        return out;
    }

    long readInt(int size) throws IOException {
        return readInt(stream.readAll(size));
    }

    public Object readOptional(Class<?> targetClass) throws IOException {
        boolean present = readBoolean();
        if (!present) {
            return null;
        }

        return read(targetClass);
    }

    public Object readArray(Class<?> elemClass, int length) throws IOException {
        // If this is a byte array, read directly
        if (elemClass == Byte.class) {
            return stream.readAll(length);

        }

        // Otherwise, recursively decode entries
        Object val = Array.newInstance(elemClass, length);
        for (int i = 0; i < length; i++) {
            Object elem = read(elemClass);
            Array.set(val, i, elem);
        }
        return val;
    }

    public byte[] readOpaque() throws IOException {
        Varint size = (Varint) read(Varint.class);
        return stream.readAll(size.value);
    }

    public <E> void readList(List<E> list, Class<E> elemClass) throws IOException {
        Varint size = (Varint) read(Varint.class);
        MLSInputStream dec = new MLSInputStream(stream.slice(size.value));

        list.clear();
        while (dec.stream.available() > 0) {
            list.add((E) dec.read(elemClass));
        }
        stream.skip(size.value);
    }

    private Object readReadable(Class<?> targetClass) throws IOException {
        try{
            Constructor<?> constructor = targetClass.getDeclaredConstructor(MLSInputStream.class);
            return constructor.newInstance(this);
        } catch (NoSuchMethodException | IllegalAccessException e) {
            throw new IOException("Readable class does not have a public MLSInputStream constructor");
        } catch (InvocationTargetException e) {
            throw new IOException("InvocationTargetException: " + e.getCause().getMessage());
        } catch (InstantiationException e) {
            throw new IOException("InstantiationException: " + e.getMessage());
        }
    }
}
