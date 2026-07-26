package org.bouncycastle.pkix.jcajce;

import junit.framework.TestCase;
import org.bouncycastle.asn1.x509.ReasonFlags;

/**
 * Tests for the package-private ReasonsMask used by CRL revocation processing.
 * hasNewReasons used to collapse to a union test through an operator-precedence slip
 * ((a | b ^ a) is (a | b)), so any non-empty candidate mask appeared to carry new reasons.
 */
public class ReasonsMaskTest
    extends TestCase
{
    public void testHasNewReasons()
    {
        ReasonsMask keyCompromise = new ReasonsMask(ReasonFlags.keyCompromise);
        ReasonsMask caCompromise = new ReasonsMask(ReasonFlags.cACompromise);
        ReasonsMask both = new ReasonsMask(ReasonFlags.keyCompromise | ReasonFlags.cACompromise);

        // a disjoint mask brings new reasons
        assertTrue(keyCompromise.hasNewReasons(caCompromise));

        // a subset brings nothing new - the union-collapsed test used to get these wrong
        assertFalse(both.hasNewReasons(keyCompromise));
        assertFalse(keyCompromise.hasNewReasons(keyCompromise));
        assertFalse(keyCompromise.hasNewReasons(new ReasonsMask()));

        // an overlapping mask with an extra reason is still new
        assertTrue(keyCompromise.hasNewReasons(both));

        // nothing is new relative to all reasons, anything is new to an empty mask
        assertFalse(new ReasonsMask(ReasonsMask.ALL_REASONS).hasNewReasons(both));
        assertTrue(new ReasonsMask().hasNewReasons(caCompromise));
        assertFalse(new ReasonsMask().hasNewReasons(new ReasonsMask()));
    }

    public void testAddReasonsAndIsAllReasons()
    {
        ReasonsMask mask = new ReasonsMask();

        assertFalse(mask.isAllReasons());

        mask.addReasons(new ReasonsMask(ReasonFlags.keyCompromise));

        assertFalse(mask.isAllReasons());
        assertFalse(mask.hasNewReasons(new ReasonsMask(ReasonFlags.keyCompromise)));
        assertTrue(mask.hasNewReasons(new ReasonsMask(ReasonFlags.cACompromise)));

        mask.addReasons(new ReasonsMask(ReasonsMask.ALL_REASONS));

        assertTrue(mask.isAllReasons());
        assertFalse(mask.hasNewReasons(new ReasonsMask(ReasonFlags.unused)));

        assertTrue(new ReasonsMask(ReasonsMask.ALL_REASONS).isAllReasons());
    }
}
