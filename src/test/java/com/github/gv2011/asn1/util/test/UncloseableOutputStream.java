package com.github.gv2011.asn1.util.test;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class UncloseableOutputStream extends FilterOutputStream
{
    public UncloseableOutputStream(final OutputStream s)
    {
        super(s);
    }

    @Override
    public void close()
    {
        throw new RuntimeException("close() called on UncloseableOutputStream");
    }

    @Override
    public void write(final byte[] b, final int off, final int len) throws IOException
    {
        out.write(b, off, len);
    }
 }
