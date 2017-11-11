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


import static com.github.gv2011.util.ex.Exceptions.run;

import java.io.OutputStream;


/**
 * An output stream which copies anything written into it to another stream.
 */
public class TeeOutputStream
    extends OutputStream
{
    private final OutputStream output1;
    private final OutputStream output2;

    /**
     * Base constructor.
     *
     * @param output1 the output stream that is wrapped.
     * @param output2 a secondary stream that anything written to output1 is also written to.
     */
    public TeeOutputStream(final OutputStream output1, final OutputStream output2)
    {
        this.output1 = output1;
        this.output2 = output2;
    }

    @Override
    public void write(final byte[] buf)
    {
      run(()->{
        output1.write(buf);
        output2.write(buf);
      });
    }

    @Override
    public void write(final byte[] buf, final int off, final int len)
    {
      run(()->{
        output1.write(buf, off, len);
        output2.write(buf, off, len);
      });
     }

    @Override
    public void write(final int b)
    {
      run(()->{
        output1.write(b);
        output2.write(b);
      });
    }

    @Override
    public void flush()
    {
      run(()->{
        output1.flush();
        output2.flush();
      });
    }

    @Override
    public void close()
    {
      run(()->{
        try{output1.close();}
        finally{output2.close();}
      });
    }
}
