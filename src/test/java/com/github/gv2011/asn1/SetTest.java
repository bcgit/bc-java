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


import com.github.gv2011.asn1.ASN1Boolean;
import com.github.gv2011.asn1.ASN1EncodableVector;
import com.github.gv2011.asn1.ASN1Integer;
import com.github.gv2011.asn1.ASN1Set;
import com.github.gv2011.asn1.ASN1TaggedObject;
import com.github.gv2011.asn1.BERSet;
import com.github.gv2011.asn1.DERBitString;
import com.github.gv2011.asn1.DEROctetString;
import com.github.gv2011.asn1.DERSequence;
import com.github.gv2011.asn1.DERSet;
import com.github.gv2011.asn1.DERTaggedObject;
import com.github.gv2011.asn1.util.test.SimpleTest;
import com.github.gv2011.util.bytes.ByteUtils;
import com.github.gv2011.util.bytes.Bytes;

/**
 * Set sorting test example
 */
public class SetTest
    extends SimpleTest
{

    @Override
    public String getName()
    {
        return "Set";
    }

    private void checkedSortedSet(final int attempt, final ASN1Set s)
    {
        if (s.getObjectAt(0) instanceof ASN1Boolean
            && s.getObjectAt(1) instanceof ASN1Integer
            && s.getObjectAt(2) instanceof DERBitString
            && s.getObjectAt(3) instanceof DEROctetString)
        {
            return;
        }

        fail("sorting failed on attempt: " + attempt);
    }

    @Override
    public void performTest()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        final Bytes data = ByteUtils.parseHex("00 00 00 00 00 00 00 00 00 00");

        v.add(new DEROctetString(data));
        v.add(new DERBitString(data));
        v.add(new ASN1Integer(100));
        v.add(ASN1Boolean.getInstance(true));

        checkedSortedSet(0, new DERSet(v));

        v = new ASN1EncodableVector();
        v.add(new ASN1Integer(100));
        v.add(ASN1Boolean.getInstance(true));
        v.add(new DEROctetString(data));
        v.add(new DERBitString(data));

        checkedSortedSet(1, new DERSet(v));

        v = new ASN1EncodableVector();
        v.add(ASN1Boolean.getInstance(true));
        v.add(new DEROctetString(data));
        v.add(new DERBitString(data));
        v.add(new ASN1Integer(100));


        checkedSortedSet(2, new DERSet(v));

        v = new ASN1EncodableVector();
        v.add(new DERBitString(data));
        v.add(new DEROctetString(data));
        v.add(new ASN1Integer(100));
        v.add(ASN1Boolean.getInstance(true));

        checkedSortedSet(3, new DERSet(v));

        v = new ASN1EncodableVector();
        v.add(new DEROctetString(data));
        v.add(new DERBitString(data));
        v.add(new ASN1Integer(100));
        v.add(ASN1Boolean.getInstance(true));

        ASN1Set s = new BERSet(v);

        if (!(s.getObjectAt(0) instanceof DEROctetString))
        {
            fail("BER set sort order changed.");
        }

        // create an implicitly tagged "set" without sorting
        final ASN1TaggedObject tag = new DERTaggedObject(false, 1, new DERSequence(v));
        s = ASN1Set.getInstance(tag, false);

        if (s.getObjectAt(0) instanceof ASN1Boolean)
        {
            fail("sorted when shouldn't be.");
        }

        // equality test
        v = new ASN1EncodableVector();

        v.add(ASN1Boolean.getInstance(true));
        v.add(ASN1Boolean.getInstance(true));
        v.add(ASN1Boolean.getInstance(true));

        s = new DERSet(v);
    }

    public static void main(
        final String[]    args)
    {
        runTest(new SetTest());
    }
}
