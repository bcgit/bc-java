package java.io;

public class FilterOutputStream extends OutputStream
{
    protected OutputStream out;

    protected FilterOutputStream(OutputStream underlying)
    {
        out = underlying;
    }

    public void write(int b) throws IOException
    {
        out.write(b);
    }

    public void write(byte[] b) throws IOException
    {
        write(b, 0, b.length);
    }

    public void write(byte[] b, int offset, int length) throws IOException
    {
        if (b == null)
        {
            throw new NullPointerException();
        }
        else if ((offset < 0) || (length < 0) || ((offset + length) > b.length))
        {
            throw new IndexOutOfBoundsException();
        }
        for (int i = 0; i < length; i++)
        {
            write(b[offset + i]);
        }
    }

    public void flush() throws IOException
    {
        out.flush();
    }

    public void close() throws IOException
    {
        out.close();
    }
}
