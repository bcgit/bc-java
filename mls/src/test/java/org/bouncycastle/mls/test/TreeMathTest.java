package org.bouncycastle.mls.test;

import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.PrintTestResult;
import org.bouncycastle.mls.TreeSize;
import org.bouncycastle.mls.NodeIndex;
import org.bouncycastle.mls.LeafIndex;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class TreeMathTest
    extends TestCase
{
    private static final long leafCount;
    private static final TreeSize size;

    static {
        leafCount = 16;
        size = TreeSize.forLeaves(leafCount);
    }

    // Test tree:
    //                               X
    //               X                               X
    //       X               X               X               X
    //   X       X       X       X       X       X       X       X
    // X   X   X   X   X   X   X   X   X   X   X   X   X   X   X   X
    //
    //                     1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3
    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0
    private static final long[] expected_root =
            {0, 1, 3, 3, 7, 7, 7, 7, 15, 15, 15, 15, 15, 15, 15, 15};
    private static final long[] expected_left =
            {0, 0, 2, 1, 4, 4, 6, 3, 8, 8, 10, 9, 12, 12, 14, 7,
                    16, 16, 18, 17, 20, 20, 22, 19, 24, 24, 26, 25, 28, 28, 30};
    private static final long[] expected_right =
            {0, 2, 2, 5, 4, 6, 6, 11, 8, 10, 10, 13, 12, 14, 14, 23,
                    16, 18, 18, 21, 20, 22, 22, 27, 24, 26, 26, 29, 28, 30, 30};
    private static final long[] expected_parent =
            {1, 3, 1, 7, 5, 3, 5, 15, 9, 11, 9, 7, 13, 11, 13, 31,
                    17, 19, 17, 23, 21, 19, 21, 15, 25, 27, 25, 23, 29, 27, 29};
    private static final long[] expected_sibling =
            {2, 5, 0, 11, 6, 1, 4, 23, 10, 13, 8, 3, 14, 9, 12, 47,
                    18, 21, 16, 27, 22, 17, 20, 7, 26, 29, 24, 19, 30, 25, 28};
    private static final long[][] expected_dirpath = {
            {1L, 3L, 7L, 15L},
            {1L, 3L, 7L, 15L},
            {5L, 3L, 7L, 15L},
            {5L, 3L, 7L, 15L},
            {9L, 11L, 7L, 15L},
            {9L, 11L, 7L, 15L},
            {13L, 11L, 7L, 15L},
            {13L, 11L, 7L, 15L},
            {17L, 19L, 23L, 15L},
            {17L, 19L, 23L, 15L},
            {21L, 19L, 23L, 15L},
            {21L, 19L, 23L, 15L},
            {25L, 27L, 23L, 15L},
            {25L, 27L, 23L, 15L},
            {29L, 27L, 23L, 15L},
            {29L, 27L, 23L, 15L},
    };
    private static final long[][] expected_copath = {
            {2L, 5L, 11L, 23L},
            {0L, 5L, 11L, 23L},
            {6L, 1L, 11L, 23L},
            {4L, 1L, 11L, 23L},
            {10L, 13L, 3L, 23L},
            {8L, 13L, 3L, 23L},
            {14L, 9L, 3L, 23L},
            {12L, 9L, 3L, 23L},
            {18L, 21L, 27L, 7L},
            {16L, 21L, 27L, 7L},
            {22L, 17L, 27L, 7L},
            {20L, 17L, 27L, 7L},
            {26L, 29L, 19L, 7L},
            {24L, 29L, 19L, 7L},
            {30L, 25L, 19L, 7L},
            {28L, 25L, 19L, 7L},
    };
    private static final long[][] expected_ancestor = {
            {0, 1, 3, 3, 7, 7, 7, 7, 15, 15, 15, 15, 15, 15, 15, 15},
            {1, 2, 3, 3, 7, 7, 7, 7, 15, 15, 15, 15, 15, 15, 15, 15},
            {3, 3, 4, 5, 7, 7, 7, 7, 15, 15, 15, 15, 15, 15, 15, 15},
            {3, 3, 5, 6, 7, 7, 7, 7, 15, 15, 15, 15, 15, 15, 15, 15},
            {7, 7, 7, 7, 8, 9, 11, 11, 15, 15, 15, 15, 15, 15, 15, 15},
            {7, 7, 7, 7, 9, 10, 11, 11, 15, 15, 15, 15, 15, 15, 15, 15},
            {7, 7, 7, 7, 11, 11, 12, 13, 15, 15, 15, 15, 15, 15, 15, 15},
            {7, 7, 7, 7, 11, 11, 13, 14, 15, 15, 15, 15, 15, 15, 15, 15},
            {15, 15, 15, 15, 15, 15, 15, 15, 16, 17, 19, 19, 23, 23, 23, 23},
            {15, 15, 15, 15, 15, 15, 15, 15, 17, 18, 19, 19, 23, 23, 23, 23},
            {15, 15, 15, 15, 15, 15, 15, 15, 19, 19, 20, 21, 23, 23, 23, 23},
            {15, 15, 15, 15, 15, 15, 15, 15, 19, 19, 21, 22, 23, 23, 23, 23},
            {15, 15, 15, 15, 15, 15, 15, 15, 23, 23, 23, 23, 24, 25, 27, 27},
            {15, 15, 15, 15, 15, 15, 15, 15, 23, 23, 23, 23, 25, 26, 27, 27},
            {15, 15, 15, 15, 15, 15, 15, 15, 23, 23, 23, 23, 27, 27, 28, 29},
            {15, 15, 15, 15, 15, 15, 15, 15, 23, 23, 23, 23, 27, 27, 29, 30},
    };
    private static final long[] expected_below = {
            // This is verbose to write out with true and false, so we pack
            // the values into longs, ordered from most-significant bit to
            // least.  These values are unpacked with getExpectedBelow(i, j).
            0b1101000100000001000000000000000L,
            0b0101000100000001000000000000000L,
            0b0111000100000001000000000000000L,
            0b0001000100000001000000000000000L,
            0b0001110100000001000000000000000L,
            0b0001010100000001000000000000000L,
            0b0001011100000001000000000000000L,
            0b0000000100000001000000000000000L,
            0b0000000111010001000000000000000L,
            0b0000000101010001000000000000000L,
            0b0000000101110001000000000000000L,
            0b0000000100010001000000000000000L,
            0b0000000100011101000000000000000L,
            0b0000000100010101000000000000000L,
            0b0000000100010111000000000000000L,
            0b0000000000000001000000000000000L,
            0b0000000000000001110100010000000L,
            0b0000000000000001010100010000000L,
            0b0000000000000001011100010000000L,
            0b0000000000000001000100010000000L,
            0b0000000000000001000111010000000L,
            0b0000000000000001000101010000000L,
            0b0000000000000001000101110000000L,
            0b0000000000000001000000010000000L,
            0b0000000000000001000000011101000L,
            0b0000000000000001000000010101000L,
            0b0000000000000001000000010111000L,
            0b0000000000000001000000010001000L,
            0b0000000000000001000000010001110L,
            0b0000000000000001000000010001010L,
            0b0000000000000001000000010001011L,
    };
    public void testRoot()
    {
        for (int n = 1; n < leafCount; n++) {
            TreeSize size = TreeSize.forLeaves(n);
            assertEquals(expected_root[n-1], NodeIndex.root(size).value());
        }
    }

    public void testRelations() {
        for (int i = 0; i < size.width(); i++) {
            NodeIndex n = new NodeIndex(i);
            assertEquals(expected_left[i], n.left().value());
            assertEquals(expected_right[i], n.right().value());
            assertEquals(expected_parent[i], n.parent().value());
            assertEquals(expected_sibling[i], n.sibling().value());
        }
    }

    private List<NodeIndex> asNodeList(long[] list) {
        return Arrays.stream(list)
                .mapToObj(NodeIndex::new)
                .collect(Collectors.toList());
    }

    public void testPaths() {
        for (int i = 0; i < leafCount; i++) {
            LeafIndex li = new LeafIndex(i);
            assertEquals(asNodeList(expected_dirpath[i]), li.directPath(size));
            assertEquals(asNodeList(expected_copath[i]), li.copath(size));
        }
    }

    public void testAncestor() {
        for (int i = 0; i < leafCount; i++) {
            for (int j = 0; j < leafCount; j++) {
                LeafIndex li = new LeafIndex(i);
                LeafIndex lj = new LeafIndex(j);
                NodeIndex ancestor = li.commonAncestor(lj);
                assertEquals(expected_ancestor[i][j], ancestor.value());
            }
        }
    }

    private static boolean getExpectedBelow(long i, long j) {
        long bit = expected_below[(int) i] & (1L << (size.width() - j - 1));
        return bit != 0;
    }

    public void testIsBelow() {
        for (int i = 0; i < size.width(); i++) {
            for (int j = 0; j < size.width(); j++) {
                NodeIndex ni = new NodeIndex(i);
                NodeIndex nj = new NodeIndex(j);
                assertEquals(getExpectedBelow(i, j), ni.isBelow(nj));
            }
        }
    }

    public static TestSuite suite()
    {
        return new TestSuite(TreeMathTest.class);
    }

    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }
}
