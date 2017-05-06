package org.bouncycastle.kmip.wire.binary;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.kmip.wire.KMIPEncodable;
import org.bouncycastle.kmip.wire.KMIPEncoder;
import org.bouncycastle.kmip.wire.KMIPItem;
import org.bouncycastle.kmip.wire.KMIPType;
import org.bouncycastle.util.Strings;

public class BinaryEncoder
    implements KMIPEncoder
{
    private final OutputStream out;

    public BinaryEncoder(OutputStream out)
    {
        this.out = out;
    }

    public void output(KMIPEncodable kmipEncodable)
        throws IOException
    {
        writeItem(kmipEncodable.toKMIPItem());
    }

    private void writeItem(KMIPItem item)
            throws IOException
    {
        writeTag(item.getTag());

        out.write(item.getType());

        long length = item.getLength();

        writeLength(length);

        switch (item.getType())
        {
        case KMIPType.BIG_INTEGER:
            byte[] bigInt = ((BigInteger)item.getValue()).toByteArray();

            int padLength = (int)(length - bigInt.length);
            if (padLength != 0)
            {
                byte pad = (byte)((bigInt[0] < 0) ? 0xff : 0x00);

                for (int p = 0; p != padLength; p++)
                {
                    out.write(pad);
                }
            }
            out.write(bigInt);
            break;
        case KMIPType.BOOLEAN:
            writeLong(((Boolean)item.getValue()).booleanValue() ? 0x01 : 0x00);
            break;
        case KMIPType.BYTE_STRING:
            out.write(((byte[])item.getValue()));
            writePadFor(length);
            break;
        case KMIPType.DATE_TIME:
            writeLong(((Date)item.getValue()).getTime());
            break;
        case KMIPType.ENUMERATION:
            writeInt(((Integer)item.getValue()).intValue());
            break;
        case KMIPType.INTEGER:
            writeInt(((Integer)item.getValue()).intValue());
            break;
        case KMIPType.INTERVAL:
            writeInt(((Long)item.getValue()).intValue());
            break;
        case KMIPType.LONG_INTEGER:
            writeLong(((Long)item.getValue()).longValue());
            break;
        case KMIPType.STRUCTURE:
            for (Iterator it = ((List)item.getValue()).iterator(); it.hasNext();)
            {
                writeItem((KMIPItem)it.next());
            }
            break;
        case KMIPType.TEXT_STRING:
            out.write(Strings.toUTF8ByteArray((String)item.getValue()));
            writePadFor(length);
            break;
        }
    }

    private void writeLong(long l)
        throws IOException
    {
        out.write((int)(l >> 56));
        out.write((int)(l >> 48));
        out.write((int)(l >> 40));
        out.write((int)(l >> 32));
        out.write((int)(l >> 24));
        out.write((int)(l >> 16));
        out.write((int)(l >> 8));
        out.write((int)l);
    }

    private void writeInt(int i)
        throws IOException
    {
        out.write(i >> 24);
        out.write(i >> 16);
        out.write(i >> 8);
        out.write(i);

        out.write(0);   // padding
        out.write(0);
        out.write(0);
        out.write(0);
    }

    private void writeTag(int tag)
        throws IOException
    {
        out.write(tag >> 16);
        out.write(tag >> 8);
        out.write(tag);
    }

    private void writeLength(long length)
        throws IOException
    {
        out.write((int)(length >> 24));
        out.write((int)(length >> 16));
        out.write((int)(length >> 8));
        out.write((int)length);
    }

    private void writePadFor(long length)
        throws IOException
    {
        int padLength = 8 - (int)(length % 8);
        if (padLength != 8)
        {
            for (int p = 0; p != padLength; p++)
            {
                out.write(0);
            }
        }
    }
}
