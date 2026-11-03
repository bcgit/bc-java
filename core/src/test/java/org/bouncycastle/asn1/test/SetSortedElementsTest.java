package org.bouncycastle.asn1.test;

import java.io.IOException;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

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

    private static final int CONCURRENT_COUNT = 2000;
    private static final int CONCURRENT_THREADS = 8;
    private static final int CONCURRENT_TRIALS = 25;

    /**
     * Holds the encoders back until all of them have started, so that they reach the SET together.
     */
    private static class StartGate
    {
        volatile boolean open;
    }

    /**
     * The first DER encoding of a SET not built in DER order - every SET the parser reads - sorts a
     * copy of the elements and caches it. The copy used to be cached before it was sorted, so another
     * thread encoding the same SET at the same time could take it unsorted, or part way through the
     * sort with some elements present twice and others missing. With the early publication nearly
     * every concurrent encoding here came out wrong; a pass cannot prove the race absent, but a
     * failure is never spurious.
     */
    public void testConcurrentFirstDEREncoding()
        throws Exception
    {
        // descending order, so the cached copy is wrong for as long as it is unsorted
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (int i = CONCURRENT_COUNT; i > 0; --i)
        {
            v.add(new DEROctetString(Pack.intToBigEndian(i)));
        }

        byte[] dlEncoding = new DLSet(v).getEncoded(ASN1Encoding.DL);
        byte[] expected = new DERSet(v).getEncoded(ASN1Encoding.DER);

        for (int trial = 0; trial != CONCURRENT_TRIALS; ++trial)
        {
            final ASN1Set shared = ASN1Set.getInstance(dlEncoding);
            final StartGate gate = new StartGate();
            final byte[][] results = new byte[CONCURRENT_THREADS][];
            final Throwable[] failures = new Throwable[CONCURRENT_THREADS];

            Thread[] threads = new Thread[CONCURRENT_THREADS];
            for (int t = 0; t != CONCURRENT_THREADS; ++t)
            {
                final int index = t;
                threads[t] = new Thread()
                {
                    public void run()
                    {
                        while (!gate.open)
                        {
                            Thread.yield();
                        }

                        try
                        {
                            results[index] = shared.getEncoded(ASN1Encoding.DER);
                        }
                        catch (Throwable e)
                        {
                            failures[index] = e;
                        }
                    }
                };
                threads[t].start();
            }

            gate.open = true;

            for (int t = 0; t != CONCURRENT_THREADS; ++t)
            {
                threads[t].join();
            }

            for (int t = 0; t != CONCURRENT_THREADS; ++t)
            {
                if (failures[t] != null)
                {
                    fail("trial " + trial + ", thread " + t + ": " + failures[t]);
                }
                assertTrue("trial " + trial + ", thread " + t + ": wrong DER encoding",
                    Arrays.areEqual(expected, results[t]));
            }
        }
    }
}
