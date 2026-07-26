package org.bouncycastle.mls.test;

import junit.framework.TestCase;

import org.bouncycastle.mls.GroupKeySet;
import org.bouncycastle.mls.TreeKEM.LeafIndex;
import org.bouncycastle.mls.TreeSize;
import org.bouncycastle.mls.crypto.MlsCipherSuite;
import org.bouncycastle.mls.crypto.Secret;

// Regression test for the negative/oversized leaf_index DoS in hasLeaf (scrutineer Finding #179).
public class GroupKeySetTest
    extends TestCase
{
    public void testOutOfRangeSenderIsNotALeaf()
        throws Exception
    {
        MlsCipherSuite suite = MlsCipherSuite.getSuite(MlsCipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);
        GroupKeySet keys = new GroupKeySet(suite, TreeSize.forLeaves(4), new Secret(new byte[suite.getKDF().getHashLength()]));

        assertTrue(keys.hasLeaf(new LeafIndex(2)));
        assertFalse(keys.hasLeaf(new LeafIndex(-1)));
        assertFalse(keys.hasLeaf(new LeafIndex(Integer.MIN_VALUE)));
        assertFalse(keys.hasLeaf(new LeafIndex(100)));
    }
}
