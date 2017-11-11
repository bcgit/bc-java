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


import static com.github.gv2011.util.ex.Exceptions.call;

import java.io.BufferedReader;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;

import com.github.gv2011.asn1.util.encoders.Base64;

/**
 * A generic PEM reader, based on the format outlined in RFC 1421
 */
public class PemReader
    extends BufferedReader
{
    private static final String BEGIN = "-----BEGIN ";
    private static final String END = "-----END ";

    public PemReader(final Reader reader)
    {
        super(reader);
    }



    @Override
    public String readLine(){
      return call(super::readLine);
    }



    public PemObject readPemObject()
    {
        String line = readLine();

        while (line != null && !line.startsWith(BEGIN))
        {
            line = readLine();
        }

        if (line != null)
        {
            line = line.substring(BEGIN.length());
            final int index = line.indexOf('-');
            final String type = line.substring(0, index);

            if (index > 0)
            {
                return loadObject(type);
            }
        }

        return null;
    }

    private PemObject loadObject(final String type)
    {
        String          line;
        final String          endMarker = END + type;
        final StringBuffer    buf = new StringBuffer();
        final List<PemHeader>            headers = new ArrayList<>();

        while ((line = readLine()) != null)
        {
            if (line.indexOf(":") >= 0)
            {
                final int index = line.indexOf(':');
                final String hdr = line.substring(0, index);
                final String value = line.substring(index + 1).trim();

                headers.add(new PemHeader(hdr, value));

                continue;
            }

            if (line.indexOf(endMarker) != -1)
            {
                break;
            }

            buf.append(line.trim());
        }

        if (line == null)
        {
            throw new PemGenerationException(endMarker + " not found");
        }

        return new PemObject(type, headers, Base64.decode(buf.toString()));
    }

}
