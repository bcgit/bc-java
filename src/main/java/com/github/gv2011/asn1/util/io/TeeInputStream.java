package com.github.gv2011.asn1.util.io;

/*-
 * #%L
 * Vinz ASN.1
 * %%
 * Copyright (C) 2016 - 2017 Vinz (https://github.com/gv2011)
 * %%
 * Please note this should be read in the same way as the MIT license. (https://www.bouncycastle.org/licence.html)
 * 
 * Copyright (c) 2000-2015 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software 
 * and associated documentation files (the "Software"), to deal in the Software without restriction, 
 * including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 * #L%
 */


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
