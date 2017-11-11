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


import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.github.gv2011.util.bytes.Bytes;

/**
 * A generic PEM object - type, header properties, and byte content.
 */
public class PemObject
    implements PemObjectGenerator
{
    private static final List<?> EMPTY_LIST = Collections.unmodifiableList(new ArrayList<>());

    private final String type;
    private final List<?>   headers;
    private final Bytes content;

    /**
     * Generic constructor for object without headers.
     *
     * @param type pem object type.
     * @param content the binary content of the object.
     */
    public PemObject(final String type, final Bytes content)
    {
        this(type, EMPTY_LIST, content);
    }

    /**
     * Generic constructor for object with headers.
     *
     * @param type pem object type.
     * @param headers a list of PemHeader objects.
     * @param content the binary content of the object.
     */
    public PemObject(final String type, final List<?> headers, final Bytes content)
    {
        this.type = type;
        this.headers = Collections.unmodifiableList(headers);
        this.content = content;
    }

    public String getType()
    {
        return type;
    }

    public List<?> getHeaders()
    {
        return headers;
    }

    public Bytes getContent()
    {
        return content;
    }

    @Override
    public PemObject generate()
        throws PemGenerationException
    {
        return this;
    }
}
