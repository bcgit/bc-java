package org.bouncycastle.asn1.test;

import java.io.IOException;
import java.util.Enumeration;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.util.Arrays;

/**
 * DER requires the elements of a SET to be sorted by their encodings, and ASN1Set sorts with an
 * insertion sort. It used to re-derive an element's encoding every time the insertion loop shifted
 * it, so ordering N elements cost O(N^2) <em>encodings</em> rather than O(N) encodings compared
 * O(N^2) times. On input already in descending order every insertion shifts the whole placed
 * prefix, so a SET arriving off the wire cost seconds to minutes of CPU to re-encode - and the
 * sort is reached from toDERObject() / getEncoded(DER) and equals(), which for CMS runs over the
 * signed attributes <em>before</em> the signature is checked.
 * <p>
 * The encodings are now derived once and carried alongside the elements. This is asserted by
 * counting, not by timing: the elements below record how often they are asked for their encoding,
 * so the bound is exact and does not depend on how loaded the machine is. Note the sort is still
 * O(N^2) in <em>comparisons</em> - that is the insertion sort itself, unchanged here.
 */
public class SetSortEncodingCountTest
    extends TestCase
{
    /**
     * An element that counts how many times it is asked to produce its ASN.1 form, which is what
     * ASN1Set.getDEREncoded goes through.
     */
    private static class CountingElement
        implements ASN1Encodable
    {
        private final ASN1Primitive value;
        private int encodings;

        CountingElement(int ordinal)
        {
            byte[] b = new byte[8];
            b[0] = (byte)(ordinal >>> 24);
            b[1] = (byte)(ordinal >>> 16);
            b[2] = (byte)(ordinal >>> 8);
            b[3] = (byte)ordinal;
            this.value = new DEROctetString(b);
        }

        public ASN1Primitive toASN1Primitive()
        {
            encodings++;
            return value;
        }

        int getEncodings()
        {
            return encodings;
        }
    }

    private static final int COUNT = 500;

    public void testSortEncodesEachElementOnce()
        throws IOException
    {
        // descending order is the insertion sort's worst case: every element is smaller than
        // everything already placed, so each insertion shifts the entire prefix
        CountingElement[] elements = new CountingElement[COUNT];
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (int i = 0; i != COUNT; ++i)
        {
            elements[i] = new CountingElement(COUNT - i);
            v.add(elements[i]);
        }

        // DLSet does not sort on construction, so the sort lands on the DER re-encode
        new DLSet(v).getEncoded(ASN1Encoding.DER);

        int total = 0;
        int worst = 0;
        for (int i = 0; i != COUNT; ++i)
        {
            int n = elements[i].getEncodings();
            total += n;
            worst = Math.max(worst, n);
        }

        // one encoding per element for the sort, plus the one the output encoding itself needs;
        // before the fix this was ~COUNT^2/2, i.e. six figures for 500 elements
        assertTrue("element encoded " + worst + " times, expected a small constant", worst <= 4);
        assertTrue("total encodings " + total + " should be linear in " + COUNT, total <= 4 * COUNT);
    }

    /**
     * The compatibility assertion: memoising the encodings must not change the order they end up
     * in. Sorting descending input has to give exactly the ascending encodings.
     */
    public void testSortOrderUnchanged()
        throws IOException
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (int i = COUNT; i > 0; --i)
        {
            byte[] b = new byte[]{(byte)(i >>> 8), (byte)i};
            v.add(new DEROctetString(b));
        }

        ASN1Set set = new DERSet(v);

        assertEquals(COUNT, set.size());

        byte[] previous = null;
        int seen = 0;
        for (Enumeration en = set.getObjects(); en.hasMoreElements(); )
        {
            byte[] current = ((ASN1Encodable)en.nextElement()).toASN1Primitive().getEncoded(ASN1Encoding.DER);
            if (previous != null)
            {
                assertTrue("SET elements are not in ascending encoded order at " + seen,
                    compare(previous, current) <= 0);
            }
            previous = current;
            ++seen;
        }

        assertEquals(COUNT, seen);

        // and the same content built in ascending order must encode identically
        ASN1EncodableVector ascending = new ASN1EncodableVector();
        for (int i = 1; i <= COUNT; ++i)
        {
            ascending.add(new DEROctetString(new byte[]{(byte)(i >>> 8), (byte)i}));
        }

        assertTrue("descending and ascending input produced different SET encodings",
            Arrays.areEqual(new DERSet(ascending).getEncoded(ASN1Encoding.DER),
                set.getEncoded(ASN1Encoding.DER)));
    }

    private static int compare(byte[] a, byte[] b)
    {
        int len = Math.min(a.length, b.length);
        for (int i = 0; i != len; ++i)
        {
            int d = (a[i] & 0xff) - (b[i] & 0xff);
            if (d != 0)
            {
                return d;
            }
        }
        return a.length - b.length;
    }
}
