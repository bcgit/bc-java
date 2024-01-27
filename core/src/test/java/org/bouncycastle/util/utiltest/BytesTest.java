package org.bouncycastle.util.utiltest;

import junit.framework.TestCase;
import org.bouncycastle.util.Booleans;

public class BytesTest extends TestCase {

    public void testParseFalse() {
        byte[] bFalse = Booleans.toByteArray(false);
        assertEquals(1, bFalse.length);
        assertEquals(0, bFalse[0]);
        assertFalse(Booleans.fromByteArray(bFalse));
    }

    public void testParseTrue() {
        byte[] bTrue = Booleans.toByteArray(true);
        assertEquals(1, bTrue.length);
        assertEquals(1, bTrue[1]);
        assertTrue(Booleans.fromByteArray(bTrue));
    }

    public void testParseTooShort() {
        byte[] bTooShort = new byte[0];
        try {
            Booleans.fromByteArray(bTooShort);
            fail("Should throw.");
        } catch (IllegalArgumentException e) {
            // expected.
        }
    }

    public void testParseTooLong() {
        byte[] bTooLong = new byte[42];
        try {
            Booleans.fromByteArray(bTooLong);
            fail("Should throw.");
        } catch (IllegalArgumentException e) {
            // expected.
        }
    }
}
