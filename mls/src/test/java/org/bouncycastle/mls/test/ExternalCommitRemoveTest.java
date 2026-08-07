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
 * validated one. Two things followed. The removed leaf index reached {@code applyRemove} straight
 * off the wire, so a Remove naming a leaf outside the tree escaped as an unchecked exception out of
 * {@code Group.handle} instead of being rejected as an invalid proposal list. And nothing tied the
 * removed leaf to the joiner, so an external party - who by design needs only the group's public
 * GroupInfo - could evict any member it named.
 * <p>
 * RFC 9420 sec. 12.2 allows "at most one Remove proposal, with which the joiner removes an old
 * version of themselves", requiring the LeafNode in the commit's path field to meet the criteria it
 * would have to meet in an Update for the removed leaf. The external path still cannot simply call
 * {@code validateRemove}, which rejects self-removes outright - a resync commit legitimately
 * removes a leaf the joiner owns - so ownership is established by comparing credentials instead.
 * <p>
 * These drive the private validator directly: reaching it through {@code Group.handle} needs a
 * fully-formed external commit with a valid UpdatePath, which would test the tree machinery rather
 * than this branch.
 */
public class ExternalCommitRemoveTest
    extends TestCase
{
    private static final short SUITE_ID = MlsCipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    private static final String FOUNDER = "founder";

    public void testExternalCommitRemoveOutsideTreeIsRejected()
        throws Exception
    {
        Group group = createFounderGroup();

        // a joiner whose credential does match the founder's, so the bounds check is the only
        // thing that can reject these
        LeafNode joiner = createLeafNode(FOUNDER);

        // the founder group has a single leaf, so every one of these is out of the tree; the
        // negative values are the wire uint32s that used to wrap to an in-range node index
        int[] outside = new int[]{ 1, 1000, Integer.MAX_VALUE, Integer.MIN_VALUE, -1 };

        for (int i = 0; i != outside.length; i++)
        {
            assertFalse("external commit Remove of leaf " + outside[i] + " should be rejected",
                validateExternal(group, externalCommitRemoving(outside[i]), joiner));
        }
    }

    /**
     * The compatibility assertion: the resync case still validates - an external commit whose
     * joiner leaf carries the same credential as the leaf it removes is the one case RFC 9420
     * sec. 12.2 permits, and it is why the external path cannot reuse validateRemove's
     * self-remove check.
     */
    public void testExternalCommitResyncOfOwnLeafIsAccepted()
        throws Exception
    {
        Group group = createFounderGroup();

        assertTrue("external commit removing the joiner's own prior leaf should validate",
            validateExternal(group, externalCommitRemoving(0), createLeafNode(FOUNDER)));
    }

    /**
     * The finding: an external joiner naming somebody else's leaf is not resyncing, it is
     * evicting a member it was never authorised to touch.
     */
    public void testExternalCommitRemoveOfAnotherMemberIsRejected()
        throws Exception
    {
        Group group = createFounderGroup();

        assertFalse("external commit removing a leaf belonging to another member should be rejected",
            validateExternal(group, externalCommitRemoving(0), createLeafNode("mallory")));
    }

    /**
     * A Remove with no joiner leaf to check it against cannot be shown to be a resync, so it is
     * refused rather than trusted - an external commit is required to carry a path field anyway
     * (RFC 9420 sec. 12.4.3.2).
     */
    public void testExternalCommitRemoveWithoutJoinerLeafIsRejected()
        throws Exception
    {
        Group group = createFounderGroup();

        assertFalse("external commit Remove with no joiner leaf should be rejected",
            validateExternal(group, externalCommitRemoving(0), null));
    }

    public void testExternalCommitWithoutRemoveIsUnaffected()
        throws Exception
    {
        Group group = createFounderGroup();

        List<CachedProposal> proposals = new ArrayList<CachedProposal>();
        proposals.add(new CachedProposal(new byte[0], Proposal.externalInit(new byte[32]), null));

        assertTrue("a lone ExternalInit should still validate",
            validateExternal(group, proposals, createLeafNode("newcomer")));
    }

    private List<CachedProposal> externalCommitRemoving(int leaf)
    {
        // an external commit must carry exactly one ExternalInit; the Remove rides alongside it
        List<CachedProposal> proposals = new ArrayList<CachedProposal>();
        proposals.add(new CachedProposal(new byte[0], Proposal.externalInit(new byte[32]), null));
        proposals.add(new CachedProposal(new byte[0], Proposal.remove(new LeafIndex(leaf)), null));
        return proposals;
    }

    private boolean validateExternal(Group group, List<CachedProposal> proposals, LeafNode joinerLeaf)
        throws Exception
    {
        Method m = Group.class.getDeclaredMethod("validateExternalCachedProposals", List.class, LeafNode.class);
        m.setAccessible(true);
        return ((Boolean)m.invoke(group, proposals, joinerLeaf)).booleanValue();
    }

    private static LeafNode createLeafNode(String identity)
        throws Exception
    {
        MlsCipherSuite suite = MlsCipherSuite.getSuite(SUITE_ID);

        AsymmetricCipherKeyPair leafKeyPair = suite.getHPKE().generatePrivateKey();
        AsymmetricCipherKeyPair sigKeyPair = suite.generateSignatureKeyPair();

        return new LeafNode(
            suite,
            suite.getHPKE().serializePublicKey(leafKeyPair.getPublic()),
            suite.serializeSignaturePublicKey(sigKeyPair.getPublic()),
            Credential.forBasic(Strings.toByteArray(identity)),
            new Capabilities(),
            new LifeTime(),
            new ArrayList<Extension>(),
            suite.serializeSignaturePrivateKey(sigKeyPair.getPrivate())
        );
    }

    // Establishes a single-member group, mirroring NewMemberMessageNPETest.
    private Group createFounderGroup()
        throws Exception
    {
        MlsCipherSuite suite = MlsCipherSuite.getSuite(SUITE_ID);
        byte[] groupID = Strings.toByteArray("external-remove-test-group");

        AsymmetricCipherKeyPair leafKeyPair = suite.getHPKE().generatePrivateKey();
        AsymmetricCipherKeyPair sigKeyPair = suite.generateSignatureKeyPair();
        Credential cred = Credential.forBasic(Strings.toByteArray(FOUNDER));

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
