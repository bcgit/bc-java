package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Stream that produces output based on the default encoding for the passed in objects.
 */
public class ASN1OutputStream
{
    public static ASN1OutputStream create(OutputStream out)
    {
        return new ASN1OutputStream(out);
    }

    public static ASN1OutputStream create(OutputStream out, String encoding)
    {
        if (encoding.equals(ASN1Encoding.DER))
        {
            return new DEROutputStream(out);
        }
        else if (encoding.equals(ASN1Encoding.DL))
        {
            return new DLOutputStream(out);
        }
        else
        {
            return new ASN1OutputStream(out);
        }
    }

    private OutputStream os;

    ASN1OutputStream(OutputStream os)
    {
        this.os = os;
    }

    public void close() throws IOException
    {
        os.close();
    }

    public void flush() throws IOException
    {
        os.flush();
    }

    public final void writeObject(ASN1Encodable encodable) throws IOException
    {
        if (null == encodable)
        {
            throw new IOException("null object detected");
        }

        writePrimitive(encodable.toASN1Primitive(), true);
        flushInternal();
    }

    public final void writeObject(ASN1Primitive primitive) throws IOException
    {
        if (null == primitive)
        {
            throw new IOException("null object detected");
        }

        writePrimitive(primitive, true);
        flushInternal();
    }

    void flushInternal() throws IOException
    {
        // Placeholder to support future internal buffering
    }

    DEROutputStream getDERSubStream()
    {
        return new DEROutputStream(os);
    }

    DLOutputStream getDLSubStream()
    {
        return new DLOutputStream(os);
    }

    final void writeDL(int length) throws IOException
    {
        if (length < 128)
        {
            write(length);
        }
        else
        {
            byte[] stack = new byte[5];
            int pos = stack.length;

            do
            {
                stack[--pos] = (byte)length;
                length >>>= 8;
            }
            while (length != 0);

            int count = stack.length - pos;
            stack[--pos] = (byte)(0x80 | count);

            write(stack, pos, count + 1);
        }
    }

    final void write(int b) throws IOException
    {
        os.write(b);
    }

    final void write(byte[] bytes, int off, int len) throws IOException
    {
        os.write(bytes, off, len);
    }

    void writeElements(ASN1Encodable[] elements)
        throws IOException
    {
        for (int i = 0, count = elements.length; i < count; ++i)
        {
            elements[i].toASN1Primitive().encode(this, true);
        }
    }

    final void writeEncodingDL(boolean withID, int identifier, byte contents) throws IOException
    {
        writeIdentifier(withID, identifier);
        writeDL(1);
        write(contents);
    }

    final void writeEncodingDL(boolean withID, int identifier, byte[] contents) throws IOException
    {
        writeIdentifier(withID, identifier);
        writeDL(contents.length);
        write(contents, 0, contents.length);
    }

    final void writeEncodingDL(boolean withID, int identifier, byte[] contents, int contentsOff, int contentsLen)
        throws IOException
    {
        writeIdentifier(withID, identifier);
        writeDL(contentsLen);
        write(contents, contentsOff, contentsLen);
    }

    final void writeEncodingDL(boolean withID, int identifier, byte contentsPrefix, byte[] contents, int contentsOff,
        int contentsLen) throws IOException
    {
        writeIdentifier(withID, identifier);
        writeDL(1 + contentsLen);
        write(contentsPrefix);
        write(contents, contentsOff, contentsLen);
    }

    final void writeEncodingDL(boolean withID, int identifier, byte[] contents, int contentsOff, int contentsLen,
        byte contentsSuffix) throws IOException
    {
        writeIdentifier(withID, identifier);
        writeDL(contentsLen + 1);
        write(contents, contentsOff, contentsLen);
        write(contentsSuffix);
    }

    final void writeEncodingDL(boolean withID, int flags, int tag, byte[] contents) throws IOException
    {
        writeIdentifier(withID, flags, tag);
        writeDL(contents.length);
        write(contents, 0, contents.length);
    }

    final void writeEncodingIL(boolean withID, int identifier, ASN1Encodable[] elements) throws IOException
    {
        writeIdentifier(withID, identifier);
        write(0x80);
        writeElements(elements);
        write(0x00);
        write(0x00);
    }

    final void writeIdentifier(boolean withID, int identifier) throws IOException
    {
        if (withID)
        {
            write(identifier);
        }
    }

    final void writeIdentifier(boolean withID, int flags, int tag) throws IOException
    {
        if (!withID)
        {
            // Don't write the identifier
        }
        else if (tag < 31)
        {
            write(flags | tag);
        }
        else
        {
            byte[] stack = new byte[6];
            int pos = stack.length;

            stack[--pos] = (byte)(tag & 0x7F);
            while (tag > 127)
            {
                tag >>>= 7;
                stack[--pos] = (byte)(tag & 0x7F | 0x80);
            }

            stack[--pos] = (byte)(flags | 0x1F);

            write(stack, pos, stack.length - pos);
        }
    }

    void writePrimitive(ASN1Primitive primitive, boolean withID) throws IOException
    {
        primitive.encode(this, withID);
    }

    void writePrimitives(ASN1Primitive[] primitives) throws IOException
    {
        for (int i = 0, count = primitives.length; i < count; ++i)
        {
            primitives[i].encode(this, true);
        }
    }

    static int getLengthOfDL(int dl)
    {
        if (dl < 128)
        {
            return 1;
        }

        int length = 2;
        while ((dl >>>= 8) != 0)
        {
            ++length;
        }
        return length;
    }

    static int getLengthOfEncodingDL(boolean withID, int contentsLength)
    {
        return (withID ? 1 : 0) + getLengthOfDL(contentsLength) + contentsLength;
    }

    static int getLengthOfIdentifier(int tag)
    {
        if (tag < 31)
        {
            return 1;
        }

        int length = 2;
        while ((tag >>>= 7) != 0)
        {
            ++length;
        }
        return length;
    }
}
