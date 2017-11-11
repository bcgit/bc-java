package com.github.gv2011.asn1.util.io.pem;

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

import java.io.BufferedWriter;
import java.io.Writer;
import java.util.Iterator;

import com.github.gv2011.asn1.util.Strings;
import com.github.gv2011.asn1.util.encoders.Base64;
import com.github.gv2011.util.bytes.Bytes;

/**
 * A generic PEM writer, based on RFC 1421
 */
public class PemWriter
    extends BufferedWriter
{
    private static final int LINE_LENGTH = 64;

    private final int nlLength;
    private final char[]  buf = new char[LINE_LENGTH];

    /**
     * Base constructor.
     *
     * @param out output stream to use.
     */
    public PemWriter(final Writer out)
    {
        super(out);

        final String nl = Strings.lineSeparator();
        if (nl != null)
        {
            nlLength = nl.length();
        }
        else
        {
            nlLength = 2;
        }
    }

    /**
     * Return the number of bytes or characters required to contain the
     * passed in object if it is PEM encoded.
     *
     * @param obj pem object to be output
     * @return an estimate of the number of bytes
     */
    public int getOutputSize(final PemObject obj)
    {
        // BEGIN and END boundaries.
        int size = (2 * (obj.getType().length() + 10 + nlLength)) + 6 + 4;

        if (!obj.getHeaders().isEmpty())
        {
            for (final Iterator<?> it = obj.getHeaders().iterator(); it.hasNext();)
            {
                final PemHeader hdr = (PemHeader)it.next();

                size += hdr.getName().length() + ": ".length() + hdr.getValue().length() + nlLength;
            }

            size += nlLength;
        }

        // base64 encoding
        final int dataLen = ((obj.getContent().size() + 2) / 3) * 4;

        size += dataLen + (((dataLen + LINE_LENGTH - 1) / LINE_LENGTH) * nlLength);

        return size;
    }

    public void writeObject(final PemObjectGenerator objGen)
    {
        final PemObject obj = objGen.generate();

        writePreEncapsulationBoundary(obj.getType());

        if (!obj.getHeaders().isEmpty())
        {
            for (final Iterator<?> it = obj.getHeaders().iterator(); it.hasNext();)
            {
                final PemHeader hdr = (PemHeader)it.next();

                this.write(hdr.getName());
                this.write(": ");
                this.write(hdr.getValue());
                newLine();
            }

            newLine();
        }

        writeEncoded(obj.getContent());
        writePostEncapsulationBoundary(obj.getType());
    }

    private void writeEncoded(Bytes bytes){
        bytes = Base64.encode(bytes);

        for (int i = 0; i < bytes.size(); i += buf.length)
        {
            int index = 0;

            while (index != buf.length)
            {
                if ((i + index) >= bytes.size())
                {
                    break;
                }
                buf[index] = (char)bytes.getByte(i + index);
                index++;
            }
            final int i0=index;
            run(()->{
              this.write(buf, 0, i0);
              newLine();
            });
        }
    }

    private void writePreEncapsulationBoundary(
        final String type)
    {
        this.write("-----BEGIN " + type + "-----");
        newLine();
    }

    private void writePostEncapsulationBoundary(
        final String type)
    {
        this.write("-----END " + type + "-----");
        newLine();
    }

    @Override
    public void newLine(){
      run(super::newLine);
    }

    @Override
    public void write(final String str){
      run(()->super.write(str));
    }


}
