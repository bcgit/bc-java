package com.github.gv2011.asn1;

import static com.github.gv2011.util.bytes.ByteUtils.newBytes;
import static com.github.gv2011.util.ex.Exceptions.run;

import java.io.IOException;
import java.io.OutputStream;

import com.github.gv2011.util.bytes.Bytes;

/**
 * Stream that produces output based on the default encoding for the passed in objects.
 */
public class ASN1OutputStream
{
    private final OutputStream os;

    public ASN1OutputStream(
        final OutputStream    os)
    {
        this.os = os;
    }

    void writeLength(
        final int length)
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

    void write(final int b)
    {
        run(()->os.write(b));
    }

    void write(final Bytes bytes)
    {
      bytes.write(os);
    }

    void writeEncoded(
        final int     tag,
        final Bytes  bytes)
    {
        write(tag);
        writeLength(bytes.size());
        write(bytes);
    }

    void writeTag(final int flags, int tagNo)
    {
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
                final byte[] stack = new byte[5];
                int pos = stack.length;

                stack[--pos] = (byte)(tagNo & 0x7F);

                do
                {
                    tagNo >>= 7;
                    stack[--pos] = (byte)(tagNo & 0x7F | 0x80);
                }
                while (tagNo > 127);

                write(newBytes(stack, pos, stack.length));
            }
        }
    }

    void writeEncoded(final int flags, final int tagNo, final Bytes bytes)
    {
        writeTag(flags, tagNo);
        writeLength(bytes.size());
        write(bytes);
    }

    protected void writeNull()
        throws IOException
    {
        os.write(BERTags.NULL);
        os.write(0x00);
    }

    public void writeObject(
        final ASN1Encodable obj)
    {
        if (obj != null)
        {
            obj.toASN1Primitive().encode(this);
        }
        else
        {
            throw new RuntimeException("null object detected");
        }
    }

    void writeImplicitObject(final ASN1Primitive obj)
    {
        if (obj != null)
        {
            obj.encode(new ImplicitOutputStream(os));
        }
        else
        {
            throw new RuntimeException("null object detected");
        }
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

    ASN1OutputStream getDERSubStream()
    {
        return new DEROutputStream(os);
    }

    ASN1OutputStream getDLSubStream()
    {
        return new DLOutputStream(os);
    }

    private class ImplicitOutputStream
        extends ASN1OutputStream
    {
        private boolean first = true;

        public ImplicitOutputStream(final OutputStream os)
        {
            super(os);
        }

        @Override
        public void write(final int b)
        {
            if (first)
            {
                first = false;
            }
            else
            {
                super.write(b);
            }
        }
    }
}
