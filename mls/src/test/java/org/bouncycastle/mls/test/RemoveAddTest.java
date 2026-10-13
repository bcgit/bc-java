package org.bouncycastle.mls.test;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.mls.TreeKEM.LeafIndex;
import org.bouncycastle.mls.TreeKEM.LeafNode;
import org.bouncycastle.mls.TreeKEM.LifeTime;
import org.bouncycastle.mls.codec.AuthenticatedContent;
import org.bouncycastle.mls.codec.Capabilities;
import org.bouncycastle.mls.codec.Commit;
import org.bouncycastle.mls.codec.Credential;
import org.bouncycastle.mls.codec.Extension;
import org.bouncycastle.mls.codec.KeyPackage;
import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSMessage;
import org.bouncycastle.mls.codec.MLSOutputStream;
import org.bouncycastle.mls.codec.Proposal;
import org.bouncycastle.mls.codec.ProposalOrRef;
import org.bouncycastle.mls.codec.Sender;
import org.bouncycastle.mls.codec.Welcome;
import org.bouncycastle.mls.crypto.MlsCipherSuite;
import org.bouncycastle.mls.crypto.Secret;
import org.bouncycastle.mls.protocol.CachedProposal;
import org.bouncycastle.mls.protocol.Group;
import org.bouncycastle.util.Strings;

public class RemoveAddTest
    extends TestCase
{
    private static final MlsCipherSuite SUITE = MlsCipherSuite.BCMLS_256_DHKEMX448_AES256GCM_SHA512_Ed448;

    private static class Client
    {
        final byte[] signingPrivate;
        final byte[] signingPublic;
        final AsymmetricCipherKeyPair init;
        final AsymmetricCipherKeyPair leaf;
        final KeyPackage keyPackage;

        Client(String identity, Client previous, byte[] initKey, byte[] leafKey, boolean expired)
            throws Exception
        {
            AsymmetricCipherKeyPair signing = previous == null ? SUITE.generateSignatureKeyPair() : null;
            signingPrivate = previous == null ? SUITE.serializeSignaturePrivateKey(signing.getPrivate()) : previous.signingPrivate;
            signingPublic = previous == null ? SUITE.serializeSignaturePublicKey(signing.getPublic()) : previous.signingPublic;
            init = SUITE.getHPKE().generatePrivateKey();
            leaf = SUITE.getHPKE().generatePrivateKey();
            long now = System.currentTimeMillis() / 1000;
            MLSOutputStream lifetime = new MLSOutputStream();
            lifetime.write(now - 60);
            lifetime.write(expired ? now - 1 : now + 3600);
            LeafNode node = new LeafNode(SUITE,
                leafKey == null ? SUITE.getHPKE().serializePublicKey(leaf.getPublic()) : leafKey,
                signingPublic, Credential.forBasic(Strings.toByteArray(identity)), new Capabilities(),
                (LifeTime)MLSInputStream.decode(lifetime.toByteArray(), LifeTime.class),
                new ArrayList<Extension>(), signingPrivate);
            keyPackage = new KeyPackage(SUITE,
                initKey == null ? SUITE.getHPKE().serializePublicKey(init.getPublic()) : initKey,
                node, new ArrayList<Extension>(), signingPrivate);
        }

        Group join(Welcome welcome)
            throws Exception
        {
            return new Group(SUITE.getHPKE().serializePrivateKey(init.getPrivate()), leaf, signingPrivate,
                keyPackage, welcome, null, new HashMap<Secret, byte[]>(), new HashMap<Group.EpochRef, byte[]>());
        }
    }

    private static class Fixture
    {
        final Client committer = new Client("committer", null, null, null, false);
        final Client survivor = new Client("survivor", null, null, null, false);
        final Client target = new Client("target", null, null, null, false);
        final Group parent;
        final Group receiver;

        Fixture()
            throws Exception
        {
            Group initial = new Group(Strings.toByteArray("group"), SUITE, committer.leaf,
                committer.signingPrivate, committer.keyPackage.getLeafNode(), new ArrayList<Extension>());
            Group.GroupWithMessage result = commit(initial, Proposal.add(survivor.keyPackage), Proposal.add(target.keyPackage));
            parent = result.group;
            receiver = survivor.join(result.message.welcome);
        }

        Client replacement()
            throws Exception
        {
            return new Client("target", target, null, null, false);
        }
    }

    private static Group.GroupWithMessage commit(Group group, Proposal... proposals)
        throws Exception
    {
        byte[] entropy = new byte[64];
        new SecureRandom().nextBytes(entropy);
        return group.commit(new Secret(entropy),
            new Group.CommitOptions(new ArrayList<Proposal>(Arrays.asList(proposals)), true, true, null),
            new Group.MessageOptions(), new Group.CommitParameters(Group.NORMAL_COMMIT_PARAMS));
    }

    private static Object invoke(Group group, String name, Class<?>[] types, Object... args)
        throws Exception
    {
        Method method = Group.class.getDeclaredMethod(name, types);
        method.setAccessible(true);
        try
        {
            return method.invoke(group, args);
        }
        catch (InvocationTargetException e)
        {
            throw (Exception)e.getCause();
        }
    }

    private static byte[] signedCommit(Group group, Proposal... proposals)
        throws Exception
    {
        Commit body = new Commit();
        for (Proposal proposal : proposals)
        {
            body.getProposals().add(ProposalOrRef.forProposal(proposal));
        }
        AuthenticatedContent content = (AuthenticatedContent)invoke(group, "sign",
            new Class<?>[]{Sender.class, Commit.class, byte[].class, boolean.class},
            Sender.forMember(group.getIndex()), body, new byte[0], false);
        content.setConfirmationTag(new byte[64]);
        return MLSOutputStream.encode(invoke(group, "protect",
            new Class<?>[]{AuthenticatedContent.class, int.class}, content, 0));
    }

    private static void assertRejected(Fixture fixture, Proposal... proposals)
        throws Exception
    {
        try
        {
            commit(fixture.parent, proposals);
            fail("committer accepted invalid proposals");
        }
        catch (Exception e)
        {
            assertEquals("Invalid proposal list", e.getMessage());
        }
        try
        {
            fixture.receiver.handle(signedCommit(fixture.parent, proposals), null,
                new Group.CommitParameters(Group.NORMAL_COMMIT_PARAMS));
            fail("receiver accepted invalid proposals");
        }
        catch (Exception e)
        {
            assertEquals("Invalid proposal list", e.getMessage());
        }
        assertEquals(1L, fixture.parent.getEpoch());
        assertEquals(1L, fixture.receiver.getEpoch());
    }

    private static void corruptSignature(Object value)
        throws Exception
    {
        Field field = value.getClass().getDeclaredField("signature");
        field.setAccessible(true);
        ((byte[])field.get(value))[0] ^= 1;
    }

    private void assertReplacement(boolean addFirst)
        throws Exception
    {
        Fixture fixture = new Fixture();
        Client replacement = fixture.replacement();
        Proposal add = Proposal.add(replacement.keyPackage);
        Proposal remove = Proposal.remove(new LeafIndex(2));
        Group.GroupWithMessage result = addFirst ? commit(fixture.parent, add, remove) : commit(fixture.parent, remove, add);
        byte[] wire = MLSOutputStream.encode(result.message);
        Group received = fixture.receiver.handle(wire, null, new Group.CommitParameters(Group.NORMAL_COMMIT_PARAMS));
        Group joined = replacement.join(result.message.welcome);
        assertEquals(2L, result.group.getEpoch());
        assertEquals(2L, received.getEpoch());
        assertEquals(2L, joined.getEpoch());
        assertTrue(Arrays.equals(MLSOutputStream.encode(replacement.keyPackage.getLeafNode()),
            MLSOutputStream.encode(result.group.getTree().getLeafNode(new LeafIndex(2)))));
        for (Group group : new Group[]{received, joined})
        {
            assertTrue(Arrays.equals(MLSOutputStream.encode(result.group.getTree()), MLSOutputStream.encode(group.getTree())));
            assertTrue(Arrays.equals(result.group.getEpochAuthenticator(), group.getEpochAuthenticator()));
        }
        MLSMessage application = result.group.protect(new byte[0], new byte[]{1, 2, 3}, 0);
        assertTrue(Arrays.equals(new byte[]{1, 2, 3}, received.unprotect(application)[1]));
        assertTrue(Arrays.equals(new byte[]{1, 2, 3}, joined.unprotect(application)[1]));
        assertSame(result.group, fixture.parent.handle(wire, result.group, new Group.CommitParameters(Group.NORMAL_COMMIT_PARAMS)));
        try
        {
            fixture.target.join(result.message.welcome);
            fail("old KeyPackage accepted replacement Welcome");
        }
        catch (Exception expected)
        {
        }
    }

    public void testRemoveAdd()
        throws Exception
    {
        assertReplacement(false);
    }

    public void testAddRemove()
        throws Exception
    {
        assertReplacement(true);
    }

    public void testMissingOrUnrelatedRemove()
        throws Exception
    {
        Fixture fixture = new Fixture();
        Proposal add = Proposal.add(fixture.replacement().keyPackage);
        assertRejected(fixture, add);
        assertRejected(fixture, Proposal.remove(new LeafIndex(1)), add);
    }

    public void testDuplicateAddsAndRemoves()
        throws Exception
    {
        Fixture fixture = new Fixture();
        Proposal remove = Proposal.remove(new LeafIndex(2));
        Proposal add = Proposal.add(fixture.replacement().keyPackage);
        assertRejected(fixture, remove, add, Proposal.add(fixture.replacement().keyPackage));
        assertRejected(fixture, remove, remove, add);
    }

    public void testInvalidRemove()
        throws Exception
    {
        Fixture fixture = new Fixture();
        Proposal add = Proposal.add(fixture.replacement().keyPackage);
        assertRejected(fixture, Proposal.remove(new LeafIndex(0)), add);
        assertRejected(fixture, Proposal.remove(new LeafIndex(-1)), add);
        assertRejected(fixture, Proposal.remove(new LeafIndex(3)), add);
    }

    public void testDifferentCredential()
        throws Exception
    {
        Fixture fixture = new Fixture();
        Client replacement = new Client("different", fixture.target, null, null, false);
        assertRejected(fixture, Proposal.remove(new LeafIndex(2)), Proposal.add(replacement.keyPackage));
    }

    public void testInvalidSignatures()
        throws Exception
    {
        Fixture fixture = new Fixture();
        Client replacement = fixture.replacement();
        corruptSignature(replacement.keyPackage);
        assertRejected(fixture, Proposal.remove(new LeafIndex(2)), Proposal.add(replacement.keyPackage));
        replacement = fixture.replacement();
        corruptSignature(replacement.keyPackage.getLeafNode());
        KeyPackage signed = new KeyPackage(SUITE, replacement.keyPackage.getInitKey(),
            replacement.keyPackage.getLeafNode(), new ArrayList<Extension>(), replacement.signingPrivate);
        assertFalse(signed.verify());
        assertRejected(fixture, Proposal.remove(new LeafIndex(2)), Proposal.add(signed));
    }

    public void testExpiredKeyPackage()
        throws Exception
    {
        Fixture fixture = new Fixture();
        Client replacement = new Client("target", fixture.target, null, null, true);
        assertRejected(fixture, Proposal.remove(new LeafIndex(2)), Proposal.add(replacement.keyPackage));
    }

    public void testUpdateRemoveConflict()
        throws Exception
    {
        Fixture fixture = new Fixture();
        Client replacement = fixture.replacement();
        LeafNode update = fixture.target.keyPackage.getLeafNode().forUpdate(SUITE,
            fixture.parent.getGroupID(), new LeafIndex(2), replacement.keyPackage.getLeafNode().getEncryptionKey(),
            new Group.LeafNodeOptions(), fixture.target.signingPrivate);
        List<CachedProposal> proposals = Arrays.asList(
            new CachedProposal(new byte[0], Proposal.update(update), new LeafIndex(2)),
            new CachedProposal(new byte[0], Proposal.remove(new LeafIndex(2)), new LeafIndex(0)),
            new CachedProposal(new byte[0], Proposal.add(replacement.keyPackage), new LeafIndex(0)));
        for (Group group : new Group[]{fixture.parent, fixture.receiver})
        {
            assertEquals(Boolean.FALSE, invoke(group, "validateNormalCachedProposals",
                new Class<?>[]{List.class, LeafIndex.class}, proposals, new LeafIndex(0)));
        }
    }

    public void testEncryptionKeyReuse()
        throws Exception
    {
        Fixture fixture = new Fixture();
        byte[] key = fixture.replacement().keyPackage.getInitKey();
        Client replacement = new Client("target", fixture.target, key, key, false);
        assertRejected(fixture, Proposal.remove(new LeafIndex(2)), Proposal.add(replacement.keyPackage));
        replacement = new Client("target", fixture.target, null, fixture.target.keyPackage.getLeafNode().getEncryptionKey(), false);
        assertRejected(fixture, Proposal.remove(new LeafIndex(2)), Proposal.add(replacement.keyPackage));
    }
}
