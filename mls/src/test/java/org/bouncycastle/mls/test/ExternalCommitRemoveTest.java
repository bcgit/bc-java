package org.bouncycastle.mls.test;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.mls.TreeKEM.LeafIndex;
import org.bouncycastle.mls.TreeKEM.LeafNode;
import org.bouncycastle.mls.TreeKEM.LifeTime;
import org.bouncycastle.mls.codec.Capabilities;
import org.bouncycastle.mls.codec.Credential;
import org.bouncycastle.mls.codec.Extension;
import org.bouncycastle.mls.codec.Proposal;
import org.bouncycastle.mls.crypto.MlsCipherSuite;
import org.bouncycastle.mls.protocol.CachedProposal;
import org.bouncycastle.mls.protocol.Group;
import org.bouncycastle.util.Strings;

/**
 * Regression tests for the Remove proposal carried by an external commit.
 * <p>
 * Proposal validation splits in two: {@code validateNormalCachedProposals} runs
 * {@code validateProposal} over the list, but the external-commit path
 * ({@code SenderType.NEW_MEMBER_COMMIT}) only <em>counted</em> its Remove proposals - it never
 * validated one. The removed leaf index therefore reached {@code applyRemove} straight off the
 * wire, so a Remove naming a leaf outside the tree escaped as an unchecked exception out of
 * {@code Group.handle} instead of being rejected as an invalid proposal list.
 * <p>
 * The external path cannot simply call {@code validateRemove}, which additionally rejects
 * self-removes - an external resync Commit legitimately removes the sender's own former leaf - so
 * the two share the bounds check only.
 * <p>
 * These drive the private validator directly: reaching it through {@code Group.handle} needs a
 * fully-formed external commit with a valid UpdatePath, which would test the tree machinery rather
 * than this branch.
 */
public class ExternalCommitRemoveTest
    extends TestCase
{
    private static final short SUITE_ID = MlsCipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    public void testExternalCommitRemoveOutsideTreeIsRejected()
        throws Exception
    {
        Group group = createFounderGroup();

        // the founder group has a single leaf, so every one of these is out of the tree; the
        // negative values are the wire uint32s that used to wrap to an in-range node index
        int[] outside = new int[]{ 1, 1000, Integer.MAX_VALUE, Integer.MIN_VALUE, -1 };

        for (int i = 0; i != outside.length; i++)
        {
            assertFalse("external commit Remove of leaf " + outside[i] + " should be rejected",
                validateExternal(group, externalCommitRemoving(outside[i])));
        }
    }

    /**
     * The compatibility assertion: an external commit removing a leaf that is in the tree still
     * validates. This is the resync case, and it is why the external path cannot reuse
     * validateRemove's self-remove check.
     */
    public void testExternalCommitRemoveInsideTreeIsAccepted()
        throws Exception
    {
        Group group = createFounderGroup();

        assertTrue("external commit removing the sole in-tree leaf should validate",
            validateExternal(group, externalCommitRemoving(0)));
    }

    public void testExternalCommitWithoutRemoveIsUnaffected()
        throws Exception
    {
        Group group = createFounderGroup();

        List<CachedProposal> proposals = new ArrayList<CachedProposal>();
        proposals.add(new CachedProposal(new byte[0], Proposal.externalInit(new byte[32]), null));

        assertTrue("a lone ExternalInit should still validate", validateExternal(group, proposals));
    }

    private List<CachedProposal> externalCommitRemoving(int leaf)
    {
        // an external commit must carry exactly one ExternalInit; the Remove rides alongside it
        List<CachedProposal> proposals = new ArrayList<CachedProposal>();
        proposals.add(new CachedProposal(new byte[0], Proposal.externalInit(new byte[32]), null));
        proposals.add(new CachedProposal(new byte[0], Proposal.remove(new LeafIndex(leaf)), null));
        return proposals;
    }

    private boolean validateExternal(Group group, List<CachedProposal> proposals)
        throws Exception
    {
        Method m = Group.class.getDeclaredMethod("validateExternalCachedProposals", List.class);
        m.setAccessible(true);
        return ((Boolean)m.invoke(group, proposals)).booleanValue();
    }

    // Establishes a single-member group, mirroring NewMemberMessageNPETest.
    private Group createFounderGroup()
        throws Exception
    {
        MlsCipherSuite suite = MlsCipherSuite.getSuite(SUITE_ID);
        byte[] groupID = Strings.toByteArray("external-remove-test-group");

        AsymmetricCipherKeyPair leafKeyPair = suite.getHPKE().generatePrivateKey();
        AsymmetricCipherKeyPair sigKeyPair = suite.generateSignatureKeyPair();
        Credential cred = Credential.forBasic(Strings.toByteArray("founder"));

        LeafNode leafNode = new LeafNode(
            suite,
            suite.getHPKE().serializePublicKey(leafKeyPair.getPublic()),
            suite.serializeSignaturePublicKey(sigKeyPair.getPublic()),
            cred,
            new Capabilities(),
            new LifeTime(),
            new ArrayList<Extension>(),
            suite.serializeSignaturePrivateKey(sigKeyPair.getPrivate())
        );

        return new Group(
            groupID,
            suite,
            leafKeyPair,
            suite.serializeSignaturePrivateKey(sigKeyPair.getPrivate()),
            leafNode.copy(leafNode.getEncryptionKey()),
            new ArrayList<Extension>()
        );
    }
}
