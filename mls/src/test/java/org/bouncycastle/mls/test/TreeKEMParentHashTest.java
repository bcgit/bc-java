package org.bouncycastle.mls.test;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.mls.TreeKEM.LeafIndex;
import org.bouncycastle.mls.TreeKEM.LeafNode;
import org.bouncycastle.mls.TreeKEM.LifeTime;
import org.bouncycastle.mls.codec.Capabilities;
import org.bouncycastle.mls.codec.Credential;
import org.bouncycastle.mls.codec.Extension;
import org.bouncycastle.mls.codec.KeyPackage;
import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSMessage;
import org.bouncycastle.mls.codec.MLSOutputStream;
import org.bouncycastle.mls.codec.Proposal;
import org.bouncycastle.mls.codec.Welcome;
import org.bouncycastle.mls.crypto.MlsCipherSuite;
import org.bouncycastle.mls.crypto.Secret;
import org.bouncycastle.mls.protocol.Group;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * Regression tests for the parent hash chain {@code TreeKEMPublicKey.parentHashes} computes for an
 * UpdatePath, at the two edges of the filtered direct path (RFC 9420 secs. 4.1.2, 7.9).
 * <p>
 * An empty filtered direct path (github #2492): in a one-leaf tree the committer's leaf is the
 * root, so there are no parent hashes to compute. The root entry was dropped from the path before
 * that case was checked, so any commit that ended in a one-member tree - removing the last other
 * member, or a plain self-update in a freshly created group - threw
 * {@code IndexOutOfBoundsException} out of {@code Group.commit}.
 * <p>
 * A filtered direct path that stops below the root: when one half of the tree under the root is
 * entirely blank the root is filtered out of a committer's path in the other half, and the chain
 * has to start from the highest node actually on the path. Starting it from the root picked the
 * wrong copath child for that node, so the committer published parent hashes that verify against
 * its own (equally wrong) recomputation but not against the tree, and the next Welcome carried a
 * tree a joiner rejects. mlspp fixed the same defect in its PR #430.
 */
public class TreeKEMParentHashTest
    extends TestCase
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final byte[] AAD = Strings.toByteArray("aad");
    private static final byte[] PLAINTEXT = Strings.toByteArray("plaintext");

    private static final class Member
    {
        final MlsCipherSuite suite;
        final AsymmetricCipherKeyPair init;
        final AsymmetricCipherKeyPair leaf;
        final byte[] signingKey;
        final LeafNode node;
        final KeyPackage keyPackage;

        Member(MlsCipherSuite suite, String name)
            throws Exception
        {
            this.suite = suite;
            this.init = suite.getHPKE().generatePrivateKey();
            this.leaf = suite.getHPKE().generatePrivateKey();

            AsymmetricCipherKeyPair signing = suite.generateSignatureKeyPair();
            this.signingKey = suite.serializeSignaturePrivateKey(signing.getPrivate());
            this.node = new LeafNode(suite, suite.getHPKE().serializePublicKey(leaf.getPublic()),
                suite.serializeSignaturePublicKey(signing.getPublic()), Credential.forBasic(Strings.toByteArray(name)),
                new Capabilities(), new LifeTime(), new ArrayList<Extension>(), signingKey);
            this.keyPackage = new KeyPackage(suite, suite.getHPKE().serializePublicKey(init.getPublic()),
                node, new ArrayList<Extension>(), signingKey);
        }

        Group create()
            throws Exception
        {
            return new Group(Strings.toByteArray("singleton-group"), suite, leaf, signingKey, node,
                new ArrayList<Extension>());
        }

        Group join(Welcome welcome)
            throws Exception
        {
            return new Group(suite.getHPKE().serializePrivateKey(init.getPrivate()), leaf, signingKey, keyPackage,
                welcome, null, new HashMap<Secret, byte[]>(), new HashMap<Group.EpochRef, byte[]>());
        }
    }

    /**
     * The reported case: the creator of a two-member group removes the other member, with and
     * without forcePath (a Remove requires a path either way, RFC 9420 sec. 12.4).
     */
    public void testRemoveLastOtherMember()
        throws Exception
    {
        MlsCipherSuite[] suites = new MlsCipherSuite[]{
            MlsCipherSuite.getSuite(MlsCipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519),
            MlsCipherSuite.BCMLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
        };
        boolean[] forcePaths = new boolean[]{ true, false };

        for (int s = 0; s != suites.length; s++)
        {
            for (int f = 0; f != forcePaths.length; f++)
            {
                checkRemoveLastOtherMember(suites[s], forcePaths[f]);
            }
        }
    }

    /**
     * The same code path reached without a Remove: a forced-path empty commit by the only member.
     */
    public void testSelfUpdateInOneMemberGroup()
        throws Exception
    {
        MlsCipherSuite suite = MlsCipherSuite.getSuite(MlsCipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);
        Member alice = new Member(suite, "alice");
        Group a = alice.create();
        long epoch = a.getEpoch();

        a = commit(a, new ArrayList<Proposal>(), true).group;

        assertEquals(epoch + 1, a.getEpoch());

        // the group is still usable: a new member can join and both directions decrypt
        checkAddAndExchange(suite, a, "bob", true);
    }

    /**
     * The member at leaf 2 of a four-member group removes leaves 0 and 1, which blanks the root's
     * whole left subtree and so filters the root out of its direct path. Its tree must still pass
     * the full parent hash check, and a new member must be able to join from it.
     */
    public void testRemoveLeftSubtreeOfRoot()
        throws Exception
    {
        MlsCipherSuite suite = MlsCipherSuite.getSuite(MlsCipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);
        Member alice = new Member(suite, "alice");
        Member bob = new Member(suite, "bob");
        Member carol = new Member(suite, "carol");
        Member dave = new Member(suite, "dave");

        List<Proposal> adds = new ArrayList<Proposal>();
        adds.add(Proposal.add(bob.keyPackage));
        adds.add(Proposal.add(carol.keyPackage));
        adds.add(Proposal.add(dave.keyPackage));
        Group.GroupWithMessage join = commit(alice.create(), adds, false);
        Group c = carol.join(join.message.welcome);
        Group d = dave.join(join.message.welcome);

        assertEquals(2, c.getIndex().value());

        List<Proposal> removes = new ArrayList<Proposal>();
        removes.add(Proposal.remove(join.group.getIndex()));
        removes.add(Proposal.remove(new LeafIndex(1)));
        Group.GroupWithMessage removal = commit(c, removes, false);
        c = removal.group;

        assertTrue("committer's tree fails the parent hash check", c.getTree().verifyParentHash());

        // the other remaining member accepts the commit and agrees on the epoch
        d = d.handle(MLSOutputStream.encode(removal.message), null);
        assertTrue(Arrays.areEqual(c.getEpochAuthenticator(), d.getEpochAuthenticator()));
        assertTrue(d.getTree().verifyParentHash());

        // and a joiner verifies the tree it is sent - added without a path, so the parent hashes
        // from the removal commit are the ones the Welcome carries
        checkAddAndExchange(suite, c, "erin", false);
    }

    private void checkRemoveLastOtherMember(MlsCipherSuite suite, boolean forcePath)
        throws Exception
    {
        Member alice = new Member(suite, "alice");
        Member bob = new Member(suite, "bob");

        List<Proposal> add = new ArrayList<Proposal>();
        add.add(Proposal.add(bob.keyPackage));
        Group.GroupWithMessage join = commit(alice.create(), add, true);
        Group a = join.group;
        Group b = bob.join(join.message.welcome);

        List<Proposal> remove = new ArrayList<Proposal>();
        remove.add(Proposal.remove(b.getIndex()));
        a = commit(a, remove, forcePath).group;

        assertEquals(b.getEpoch() + 1, a.getEpoch());

        // the removed member can no longer read the group's traffic
        byte[] next = MLSOutputStream.encode(a.protect(AAD, PLAINTEXT, 0));
        try
        {
            b.unprotect((MLSMessage)MLSInputStream.decode(next, MLSMessage.class));
            fail("removed member decrypted a message from the next epoch");
        }
        catch (Exception e)
        {
            // expected
        }

        // the remaining member can go on committing in the one-member group, and re-grow it
        a = commit(a, new ArrayList<Proposal>(), true).group;
        checkAddAndExchange(suite, a, "carol", true);
    }

    private void checkAddAndExchange(MlsCipherSuite suite, Group a, String name, boolean forcePath)
        throws Exception
    {
        Member other = new Member(suite, name);
        List<Proposal> add = new ArrayList<Proposal>();
        add.add(Proposal.add(other.keyPackage));
        Group.GroupWithMessage join = commit(a, add, forcePath);
        a = join.group;
        Group o = other.join(join.message.welcome);

        assertEquals(a.getEpoch(), o.getEpoch());
        assertTrue(Arrays.areEqual(a.getEpochAuthenticator(), o.getEpochAuthenticator()));

        byte[] wire = MLSOutputStream.encode(a.protect(AAD, PLAINTEXT, 0));
        byte[][] received = o.unprotect((MLSMessage)MLSInputStream.decode(wire, MLSMessage.class));
        assertTrue(Arrays.areEqual(PLAINTEXT, received[1]));

        wire = MLSOutputStream.encode(o.protect(AAD, PLAINTEXT, 0));
        received = a.unprotect((MLSMessage)MLSInputStream.decode(wire, MLSMessage.class));
        assertTrue(Arrays.areEqual(PLAINTEXT, received[1]));
    }

    private static Group.GroupWithMessage commit(Group group, List<Proposal> proposals, boolean forcePath)
        throws Exception
    {
        byte[] leafSecret = new byte[group.getSuite().getKDF().getHashLength()];
        RANDOM.nextBytes(leafSecret);

        return group.commit(new Secret(leafSecret), new Group.CommitOptions(proposals, true, forcePath, null),
            new Group.MessageOptions(), new Group.CommitParameters(Group.NORMAL_COMMIT_PARAMS));
    }
}
