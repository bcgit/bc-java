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


import static com.github.gv2011.util.bytes.ByteUtils.newBytes;
import static com.github.gv2011.util.bytes.ByteUtils.newBytesBuilder;

import java.util.Enumeration;
import java.util.Vector;

import com.github.gv2011.util.bytes.Bytes;
import com.github.gv2011.util.bytes.BytesBuilder;

public class BEROctetString extends ASN1OctetString {

    private static final int MAX_LENGTH = 1000;

    private ASN1OctetString[] octs;

    /**
     * convert a vector of octet strings into a single byte string
     */
    static private Bytes toBytes(
        final ASN1OctetString[]  octs)
    {
      final BytesBuilder bOut = newBytesBuilder();

        for (int i = 0; i != octs.length; i++)
        {
            try
            {
                final DEROctetString o = (DEROctetString)octs[i];

                o.getOctets().write(bOut);
            }
            catch (final ClassCastException e)
            {
                throw new IllegalArgumentException(octs[i].getClass().getName() + " found in input should only contain DEROctetString");
            }
        }

        return bOut.build();
    }

    /**
     * @param string the octets making up the octet string.
     */
    public BEROctetString(
        final Bytes string)
    {
        super(string);
    }

    public BEROctetString(
        final ASN1OctetString[] octs)
    {
        super(toBytes(octs));

        this.octs = octs;
    }

    /**
     * return the DER octets that make up this string.
     */
    public Enumeration<ASN1OctetString> getObjects()
    {
        if (octs == null)
        {
            return generateOcts().elements();
        }

        return new Enumeration<ASN1OctetString>()
        {
            int counter = 0;

            @Override
            public boolean hasMoreElements()
            {
                return counter < octs.length;
            }

            @Override
            public ASN1OctetString nextElement()
            {
                return octs[counter++];
            }
        };
    }

    private Vector<ASN1OctetString> generateOcts()
    {
        final Vector<ASN1OctetString> vec = new Vector<>();
        for (int i = 0; i < string.size(); i += MAX_LENGTH)
        {
            int end;

            if (i + MAX_LENGTH > string.size())
            {
                end = string.size();
            }
            else
            {
                end = i + MAX_LENGTH;
            }

            final byte[] nStr = new byte[end - i];

            System.arraycopy(string, i, nStr, 0, nStr.length);

            vec.addElement(new DEROctetString(newBytes(nStr)));
         }

         return vec;
    }

    @Override
    boolean isConstructed()
    {
        return true;
    }

    @Override
    int encodedLength()
    {
        int length = 0;
        for (final Enumeration<ASN1OctetString> e = getObjects(); e.hasMoreElements();)
        {
            length += ((ASN1Encodable)e.nextElement()).toASN1Primitive().encodedLength();
        }

        return 2 + length + 2;
    }

    @Override
    public void encode(
        final ASN1OutputStream out)
    {
        out.write(BERTags.CONSTRUCTED | BERTags.OCTET_STRING);

        out.write(0x80);

        //
        // write out the octet array
        //
        for (final Enumeration<ASN1OctetString> e = getObjects(); e.hasMoreElements();)
        {
            out.writeObject((ASN1Encodable)e.nextElement());
        }

        out.write(0x00);
        out.write(0x00);
    }

    static BEROctetString fromSequence(final ASN1Sequence seq)
    {
        final ASN1OctetString[]     v = new ASN1OctetString[seq.size()];
        final Enumeration<ASN1Encodable> e = seq.getObjects();
        int                   index = 0;

        while (e.hasMoreElements())
        {
            v[index++] = (ASN1OctetString)e.nextElement();
        }

        return new BEROctetString(v);
    }
}
