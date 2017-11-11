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


import java.util.Enumeration;

import com.github.gv2011.util.bytes.Bytes;

/**
 * Note: this class is for processing DER/DL encoded sequences only.
 */
class LazyEncodedSequence
    extends ASN1Sequence
{
    private Bytes encoded;

    LazyEncodedSequence(
        final Bytes encoded){
        this.encoded = encoded;
    }

    private void parse()
    {
        final Enumeration<ASN1Encodable> en = new LazyConstructionEnumeration(encoded);

        while (en.hasMoreElements())
        {
            seq.addElement(en.nextElement());
        }

        encoded = null;
    }

    @Override
    public synchronized ASN1Encodable getObjectAt(final int index)
    {
        if (encoded != null)
        {
            parse();
        }

        return super.getObjectAt(index);
    }

    @Override
    public synchronized Enumeration<ASN1Encodable> getObjects()
    {
        if (encoded == null)
        {
            return super.getObjects();
        }

        return new LazyConstructionEnumeration(encoded);
    }

    @Override
    public synchronized int size()
    {
        if (encoded != null)
        {
            parse();
        }

        return super.size();
    }

    @Override
    ASN1Primitive toDERObject()
    {
        if (encoded != null)
        {
            parse();
        }

        return super.toDERObject();
    }

    @Override
    ASN1Primitive toDLObject()
    {
        if (encoded != null)
        {
            parse();
        }

        return super.toDLObject();
    }

    @Override
    int encodedLength()
    {
        if (encoded != null)
        {
            return StreamUtil.typicalLength(encoded);
        }
        else
        {
            return super.toDLObject().encodedLength();
        }
    }

    @Override
    void encode(
        final ASN1OutputStream out)
    {
        if (encoded != null)
        {
            out.writeEncoded(BERTags.SEQUENCE | BERTags.CONSTRUCTED, encoded);
        }
        else
        {
            super.toDLObject().encode(out);
        }
    }
}
