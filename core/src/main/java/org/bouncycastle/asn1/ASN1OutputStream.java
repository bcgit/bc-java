package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Enumeration;

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

    /**
     * @deprecated Use {@link ASN1OutputStream#create(OutputStream)} instead.
     */
    public ASN1OutputStream(OutputStream os)
    {
        this.os = os;
    }

    final void writeLength(
        int length)
        throws IOException
    {
        if (length > 127)
        {
            int size = 1;
            int val = length;

            while ((val >>>= 8) != 0)
            {
                size++;
            }

            write((byte)(size | 0x80));

            for (int i = (size - 1) * 8; i >= 0; i -= 8)
            {
                write((byte)(length >> i));
            }
        }
        else
        {
            write((byte)length);
        }
    }

    final void write(int b)
        throws IOException
    {
        os.write(b);
    }

    final void write(byte[] bytes, int off, int len)
        throws IOException
    {
        os.write(bytes, off, len);
    }

    final void writeElements(ASN1Encodable[] elements)
        throws IOException
    {
        int count = elements.length;
        for (int i = 0; i < count; ++i)
        {
            ASN1Primitive primitive = elements[i].toASN1Primitive();

            writePrimitive(primitive, true);
        }
    }

    final void writeElements(Enumeration elements)
        throws IOException
    {
        while (elements.hasMoreElements())
        {
            ASN1Primitive primitive = ((ASN1Encodable)elements.nextElement()).toASN1Primitive();

            writePrimitive(primitive, true);
        }
    }

    final void writeEncoded(
        boolean withTag,
        int     tag,
        byte    contents)
        throws IOException
    {
        if (withTag)
        {
            write(tag);
        }
        writeLength(1);
        write(contents);
    }

    final void writeEncoded(
        boolean withTag,
        int     tag,
        byte[]  contents)
        throws IOException
    {
        if (withTag)
        {
            write(tag);
        }
        writeLength(contents.length);
        write(contents, 0, contents.length);
    }

    final void writeEncoded(
        boolean withTag,
        int     tag,
        byte[]  contents,
        int     contentsOff,
        int     contentsLen)
        throws IOException
    {
        if (withTag)
        {
            write(tag);
        }
        writeLength(contentsLen);
        write(contents, contentsOff, contentsLen);
    }

    final void writeEncoded(
        boolean withTag,
        int     tag,
        byte    headByte,
        byte[]  tailBytes)
        throws IOException
    {
        if (withTag)
        {
            write(tag);
        }
        writeLength(1 + tailBytes.length);
        write(headByte);
        write(tailBytes, 0, tailBytes.length);
    }

    final void writeEncoded(
        boolean withTag,
        int     tag,
        byte    headByte,
        byte[]  body,
        int     bodyOff,
        int     bodyLen,
        byte    tailByte)
        throws IOException
    {
        if (withTag)
        {
            write(tag);
        }
        writeLength(2 + bodyLen);
        write(headByte);
        write(body, bodyOff, bodyLen);
        write(tailByte);
    }

    final void writeEncoded(boolean withTag, int flags, int tagNo, byte[] contents)
        throws IOException
    {
        writeTag(withTag, flags, tagNo);
        writeLength(contents.length);
        write(contents, 0, contents.length);
    }

    final void writeEncodedIndef(boolean withTag, int flags, int tagNo, byte[] contents)
        throws IOException
    {
        writeTag(withTag, flags, tagNo);
        write(0x80);
        write(contents, 0, contents.length);
        write(0x00);
        write(0x00);
    }

    final void writeEncodedIndef(boolean withTag, int tag, ASN1Encodable[] elements)
        throws IOException
    {
        if (withTag)
        {
            write(tag);
        }
        write(0x80);
        writeElements(elements);
        write(0x00);
        write(0x00);
    }

    final void writeEncodedIndef(boolean withTag, int tag, Enumeration elements)
        throws IOException
    {
        if (withTag)
        {
            write(tag);
        }
        write(0x80);
        writeElements(elements);
        write(0x00);
        write(0x00);
    }

    final void writeTag(boolean withTag, int flags, int tagNo)
        throws IOException
    {
        if (!withTag)
        {
            return;
        }

        if (tagNo < 31)
        {
            write(flags | tagNo);
        }
        else
        {
            write(flags | 0x1f);
            if (tagNo < 128)
            {
                write(tagNo);
            }
            else
            {
                byte[] stack = new byte[5];
                int pos = stack.length;

                stack[--pos] = (byte)(tagNo & 0x7F);

                do
                {
                    tagNo >>= 7;
                    stack[--pos] = (byte)(tagNo & 0x7F | 0x80);
                }
                while (tagNo > 127);

                write(stack, pos, stack.length - pos);
            }
        }
    }

    public void writeObject(ASN1Encodable obj) throws IOException
    {
        if (null == obj)
        {
            throw new IOException("null object detected");
        }

        writePrimitive(obj.toASN1Primitive(), true);
        flushInternal();
    }

    public void writeObject(ASN1Primitive primitive) throws IOException
    {
        if (null == primitive)
        {
            throw new IOException("null object detected");
        }

        writePrimitive(primitive, true);
        flushInternal();
    }

    void writePrimitive(ASN1Primitive primitive, boolean withTag) throws IOException
    {
        primitive.encode(this, withTag);
    }

    public void close()
        throws IOException
    {
        os.close();
    }

    public void flush()
        throws IOException
    {
        os.flush();
    }

    void flushInternal()
        throws IOException
    {
        // Placeholder to support future internal buffering
    }

    DEROutputStream getDERSubStream()
    {
        return new DEROutputStream(os);
    }

    ASN1OutputStream getDLSubStream()
    {
        return new DLOutputStream(os);
    }
}
