package org.bouncycastle.asn1.test;

import java.io.IOException;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.util.Arrays;

/**
 * ASN1Set keeps its elements in DER order, in sortedElements, alongside the elements themselves:
 * set at construction when that order is already known, otherwise computed and cached by the first
 * DER encoding.
 */
public class SetSortedElementsTest
    extends TestCase
{
    private static final ASN1Integer ONE = new ASN1Integer(1);
    private static final ASN1Integer TWO = new ASN1Integer(2);

    /**
     * Gives the test a view of the protected sortedElements field.
     */
    private static class ExposedDERSet
        extends DERSet
    {
        ExposedDERSet(ASN1Encodable[] elements)
        {
            super(elements);
        }

        ASN1Encodable[] getSortedElements()
        {
            return sortedElements;
        }
    }

    /**
     * The array constructor copies the caller's array, and sorts the copy for a DERSet; it used to
     * record the caller's array, unsorted, as the DER order (github #2550).
     */
    public void testDERSetArrayConstructorRecordsSortedCopy()
    {
        ASN1Encodable[] caller = new ASN1Encodable[]{ TWO, ONE };
        ExposedDERSet set = new ExposedDERSet(caller);

        ASN1Encodable[] sorted = set.getSortedElements();
        assertNotSame("sortedElements is the caller's array", caller, sorted);
        assertTrue("sortedElements not in DER order", Arrays.areEqual(new ASN1Encodable[]{ ONE, TWO }, sorted));
        assertSame(ONE, set.getObjectAt(0));
        assertSame(TWO, set.getObjectAt(1));
    }

    /**
     * A set of one element needs no sorting, so it records its elements as their DER order at
     * construction - for DLSet and BERSet too. That has to be the set's own copy: when it was the
     * caller's array, whatever the caller later stored there became the set's DER encoding and what
     * equals() compared, while getObjectAt(), hashCode() and the DL/BER encodings kept the original.
     */
    public void testSingleElementSetDoesNotRetainCallerArray()
        throws IOException
    {
        byte[] expected = new DERSet(ONE).getEncoded(ASN1Encoding.DER);

        for (int i = 0; i != 3; ++i)
        {
            ASN1Encodable[] caller = new ASN1Encodable[]{ ONE };
            ASN1Set set = (i == 0) ? (ASN1Set)new DLSet(caller) : (i == 1) ? (ASN1Set)new BERSet(caller) : new DERSet(caller);
            String name = set.getClass().getName();

            caller[0] = TWO;

            assertTrue(name + " DER encoding follows the caller's array",
                Arrays.areEqual(expected, set.getEncoded(ASN1Encoding.DER)));
            assertTrue(name + " no longer equals its own content", set.equals(new DLSet(ONE)));
            assertFalse(name + " equals the caller's later content", set.equals(new DLSet(TWO)));

            caller[0] = null;

            assertTrue(name + " DER encoding follows the caller's array",
                Arrays.areEqual(expected, set.getEncoded(ASN1Encoding.DER)));
        }
    }
}
