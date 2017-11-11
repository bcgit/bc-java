package com.github.gv2011.asn1;

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


import java.io.IOException;
import java.io.OutputStream;

/**
 * A stream generator for DER SEQUENCEs
 */
public class BERSequenceGenerator
    extends BERGenerator
{
    /**
     * Use the passed in stream as the target for the generator, writing out the header tag
     * for a constructed SEQUENCE.
     *
     * @param out target stream
     * @throws IOException if the target stream cannot be written to.
     */
    public BERSequenceGenerator(
        OutputStream out)
        throws IOException
    {
        super(out);

        writeBERHeader(BERTags.CONSTRUCTED | BERTags.SEQUENCE);
    }

    /**
     * Use the passed in stream as the target for the generator, writing out the header tag
     * for a tagged constructed SEQUENCE (possibly implicit).
     *
     * @param out target stream
     * @param tagNo the tag number to introduce
     * @param isExplicit true if this is an explicitly tagged object, false otherwise.
     * @throws IOException if the target stream cannot be written to.
     */
    public BERSequenceGenerator(
        OutputStream out,
        int tagNo,
        boolean isExplicit)
        throws IOException
    {
        super(out, tagNo, isExplicit);

        writeBERHeader(BERTags.CONSTRUCTED | BERTags.SEQUENCE);
    }

    /**
     * Add an object to the SEQUENCE being generated.
     *
     * @param object an ASN.1 encodable object to add.
     * @throws IOException if the target stream cannot be written to or the object cannot be encoded.
     */
    public void addObject(
        ASN1Encodable object)
        throws IOException
    {
        object.toASN1Primitive().encode(new BEROutputStream(_out));
    }

    /**
     * Close of the generator, writing out the BER end tag.
     *
     * @throws IOException if the target stream cannot be written.
     */
    public void close()
        throws IOException
    {
        writeBEREnd();
    }
}
