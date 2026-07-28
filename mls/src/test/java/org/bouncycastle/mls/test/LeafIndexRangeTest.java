package org.bouncycastle.mls.test;

import junit.framework.TestCase;
import org.bouncycastle.mls.TreeKEM.LeafIndex;
import org.bouncycastle.mls.TreeKEM.NodeIndex;
import org.bouncycastle.mls.TreeSize;
import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.util.encoders.Hex;

/**
 * Regression tests for out-of-range MLS leaf_index handling.
 * <p>
 * leaf_index is a uint32 on the wire, held here in a signed int, and
 * {@code NodeIndex(LeafIndex)} doubled it with an int multiply. That wrapped for any index at or
 * above 2^30: the node index went negative and then compared as less than every signed bound it
 * was checked against, so the accumulating loop in {@code LeafIndex.directPath} never reached the
 * root and ran until the heap was exhausted, and {@code commonAncestor} - which shifts its two
 * operands right until they meet - spun forever on mixed-sign values. An index of exactly 2^31 was
 * worse than a hang: it wrapped to node 0, aliasing a real leaf rather than being refused.
 * <p>
 * The fix treats the index as unsigned where it is used (the doubling is done in long arithmetic)
 * and bounds {@code LeafIndex.directPath} the way its NodeIndex counterpart already did.
 * <p>
 * Note what is deliberately <em>not</em> done: the decode constructor still accepts every uint32.
 * The RFC 9420 "messages" test vector round-trips randomly generated indices, so rejecting
 * top-bit-set values at decode would fail conformance - see {@code testDecodeRoundTripsFullRange}
 * and MLSInputStreamTest.testLargeLeafIndexRoundTrips. A decode-side bound would also not have
 * been sufficient, since an index below 2^31 still overflowed the multiply and an index that is
 * merely larger than the tree is perfectly well-formed.
 */
public class LeafIndexRangeTest
    extends TestCase
{
    private static final TreeSize SMALL_TREE = TreeSize.forLeaves(4);

    /**
     * The compatibility assertion: the full uint32 range still decodes, because the wire format
     * says so. The safety is downstream, in the tests below.
     */
    public void testDecodeRoundTripsFullRange()
        throws Exception
    {
        String[] wire = new String[]{ "00000000", "00000004", "7fffffff", "80000000", "ffffffff" };
        int[] expected = new int[]{ 0, 4, Integer.MAX_VALUE, Integer.MIN_VALUE, -1 };

        for (int i = 0; i != wire.length; i++)
        {
            LeafIndex leaf = (LeafIndex)MLSInputStream.decode(Hex.decode(wire[i]), LeafIndex.class);
            assertEquals("wire 0x" + wire[i], expected[i], leaf.value());
        }
    }

    /**
     * The node index must not wrap, whatever the leaf index. 2^31 is the case that aliased node 0
     * rather than merely going negative.
     */
    public void testNodeIndexDoesNotOverflow()
    {
        assertEquals(8L, new NodeIndex(new LeafIndex(4)).value());
        assertEquals(1L << 31, new NodeIndex(new LeafIndex(1 << 30)).value());
        assertEquals(1L << 32, new NodeIndex(new LeafIndex(Integer.MIN_VALUE)).value());
        assertEquals(2L * 0xFFFFFFFFL, new NodeIndex(new LeafIndex(-1)).value());

        for (int shift = 0; shift != 32; ++shift)
        {
            assertTrue("node index not positive for leaf bit " + shift,
                new NodeIndex(new LeafIndex(1 << shift)).value() > 0);
        }
    }

    /**
     * The sink itself: an index outside the tree must be refused rather than looped on. A plain
     * in-range value larger than the tree (4, 1000) is the case a decode-side bound could not have
     * caught; the negative values are the wire uint32s that used to wrap.
     */
    public void testDirectPathRejectsIndexOutsideTree()
    {
        int[] outside = new int[]{ 4, 1000, 1 << 30, Integer.MAX_VALUE, Integer.MIN_VALUE, -1 };

        for (int i = 0; i != outside.length; i++)
        {
            try
            {
                new LeafIndex(outside[i]).directPath(SMALL_TREE);
                fail("expected leaf index " + outside[i] + " to be refused outside a 4-leaf tree");
            }
            catch (IllegalArgumentException e)
            {
                assertEquals("Request for direct path outside of tree", e.getMessage());
            }
        }
    }

    public void testDirectPathStillWorksInsideTree()
    {
        // the compatibility assertion: every leaf of the tree still yields its path to the root
        for (int leaf = 0; leaf != 4; ++leaf)
        {
            assertEquals("unexpected direct path length for leaf " + leaf,
                2, new LeafIndex(leaf).directPath(SMALL_TREE).size());
        }
    }

    /**
     * commonAncestor shifts its two operands right until they meet; with one of them negative -
     * which the int overflow used to produce - they converge to -1 and 0 and never do. This is a
     * pure CPU spin with no allocation, so it would hang rather than raise OutOfMemoryError.
     */
    public void testCommonAncestorTerminates()
    {
        assertEquals(1L, new LeafIndex(0).commonAncestor(new LeafIndex(1)).value());

        int[] wrapping = new int[]{ 1 << 30, Integer.MAX_VALUE, Integer.MIN_VALUE, -1 };
        for (int i = 0; i != wrapping.length; i++)
        {
            assertTrue("commonAncestor did not settle on a real node for leaf " + wrapping[i],
                new LeafIndex(wrapping[i]).commonAncestor(new LeafIndex(1)).value() > 0);
        }
    }
}
