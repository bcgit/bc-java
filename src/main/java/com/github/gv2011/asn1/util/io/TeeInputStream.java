package com.github.gv2011.asn1.util.io;

import static com.github.gv2011.util.ex.Exceptions.call;
import static com.github.gv2011.util.ex.Exceptions.run;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * An input stream which copies anything read through it to another stream.
 */
public class TeeInputStream
    extends InputStream
{
    private final InputStream input;
    private final OutputStream output;

    /**
     * Base constructor.
     *
     * @param input input stream to be wrapped.
     * @param output output stream to copy any input read to.
     */
    public TeeInputStream(final InputStream input, final OutputStream output)
    {
        this.input = input;
        this.output = output;
    }

    @Override
    public int read(final byte[] buf){
        return read(buf, 0, buf.length);
    }

    @Override
    public int read(final byte[] buf, final int off, final int len){
      return call(()->{
        final int i = input.read(buf, off, len);

        if (i > 0)
        {
            output.write(buf, off, i);
        }

        return i;
      });
    }

    @Override
    public int read(){
      return call(()->{
        final int i = input.read();

        if (i >= 0)
        {
            output.write(i);
        }

        return i;
      });
    }

    @Override
    public void close(){
      run(()->{
        try{input.close();}
        finally{output.close();}
      });
    }

    public OutputStream getOutputStream()
    {
        return output;
    }
}
