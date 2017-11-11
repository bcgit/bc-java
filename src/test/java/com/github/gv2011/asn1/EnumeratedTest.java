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

import com.github.gv2011.asn1.ASN1Boolean;
import com.github.gv2011.asn1.ASN1Enumerated;
import com.github.gv2011.asn1.ASN1ObjectIdentifier;
import com.github.gv2011.asn1.ASN1Primitive;
import com.github.gv2011.asn1.ASN1Sequence;
import com.github.gv2011.asn1.util.encoders.Hex;
import com.github.gv2011.util.bytes.Bytes;

import junit.framework.TestCase;

/**
 * Tests used to verify correct decoding of the ENUMERATED type.
 */
public class EnumeratedTest
    extends TestCase
{
    /**
     * Test vector used to test decoding of multiple items. This sample uses an ENUMERATED and a BOOLEAN.
     */
    private static final Bytes MultipleSingleByteItems = Hex.decode("30060a01010101ff");

    /**
     * Test vector used to test decoding of multiple items. This sample uses two ENUMERATEDs.
     */
    private static final Bytes MultipleDoubleByteItems = Hex.decode("30080a0201010a020202");

    /**
     * Test vector used to test decoding of multiple items. This sample uses an ENUMERATED and an OBJECT IDENTIFIER.
     */
    private static final Bytes MultipleTripleByteItems = Hex.decode("300a0a0301010106032b0601");

    /**
     * Makes sure multiple identically sized values are parsed correctly.
     */
    public void testReadingMultipleSingleByteItems()
        throws IOException
    {
        final ASN1Primitive obj = ASN1Primitive.fromBytes(MultipleSingleByteItems);

        assertTrue("Null ASN.1 SEQUENCE", obj instanceof ASN1Sequence);

        final ASN1Sequence sequence = (ASN1Sequence)obj;

        assertEquals("2 items expected", 2, sequence.size());

        final ASN1Enumerated enumerated = ASN1Enumerated.getInstance(sequence.getObjectAt(0));

        assertNotNull("ENUMERATED expected", enumerated);

        assertEquals("Unexpected ENUMERATED value", 1, enumerated.getValue().intValue());

        final ASN1Boolean b = ASN1Boolean.getInstance(sequence.getObjectAt(1));

        assertNotNull("BOOLEAN expected", b);

        assertTrue("Unexpected BOOLEAN value", b.isTrue());
    }

    /**
     * Makes sure multiple identically sized values are parsed correctly.
     */
    public void testReadingMultipleDoubleByteItems()
        throws IOException
    {
        final ASN1Primitive obj = ASN1Primitive.fromBytes(MultipleDoubleByteItems);

        assertTrue("Null ASN.1 SEQUENCE", obj instanceof ASN1Sequence);

        final ASN1Sequence sequence = (ASN1Sequence)obj;

        assertEquals("2 items expected", 2, sequence.size());

        final ASN1Enumerated enumerated1 = ASN1Enumerated.getInstance(sequence.getObjectAt(0));

        assertNotNull("ENUMERATED expected", enumerated1);

        assertEquals("Unexpected ENUMERATED value", 257, enumerated1.getValue().intValue());

        final ASN1Enumerated enumerated2 = ASN1Enumerated.getInstance(sequence.getObjectAt(1));

        assertNotNull("ENUMERATED expected", enumerated2);

        assertEquals("Unexpected ENUMERATED value", 514, enumerated2.getValue().intValue());
    }

    /**
     * Makes sure multiple identically sized values are parsed correctly.
     */
    public void testReadingMultipleTripleByteItems()
        throws IOException
    {
        final ASN1Primitive obj = ASN1Primitive.fromBytes(MultipleTripleByteItems);

        assertTrue("Null ASN.1 SEQUENCE", obj instanceof ASN1Sequence);

        final ASN1Sequence sequence = (ASN1Sequence)obj;

        assertEquals("2 items expected", 2, sequence.size());

        final ASN1Enumerated enumerated = ASN1Enumerated.getInstance(sequence.getObjectAt(0));

        assertNotNull("ENUMERATED expected", enumerated);

        assertEquals("Unexpected ENUMERATED value", 65793, enumerated.getValue().intValue());

        final ASN1ObjectIdentifier objectId = ASN1ObjectIdentifier.getInstance(sequence.getObjectAt(1));

        assertNotNull("OBJECT IDENTIFIER expected", objectId);

        assertEquals("Unexpected OBJECT IDENTIFIER value", "1.3.6.1", objectId.getId());
    }
}
