package org.bouncycastle.mls.test;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.mls.TreeKEM.LeafNode;
import org.bouncycastle.mls.TreeKEM.LifeTime;
import org.bouncycastle.mls.codec.Capabilities;
import org.bouncycastle.mls.codec.Credential;
import org.bouncycastle.mls.codec.Extension;
import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSMessage;
import org.bouncycastle.mls.codec.MLSOutputStream;
import org.bouncycastle.mls.codec.Proposal;
import org.bouncycastle.mls.crypto.MlsCipherSuite;
import org.bouncycastle.mls.crypto.Secret;
import org.bouncycastle.mls.protocol.Group;
import org.bouncycastle.util.Strings;

public class SingletonRemovalTest
    extends TestCase
{
    private static final MlsCipherSuite SUITE =
        MlsCipherSuite.BCMLS_256_DHKEMX448_AES256GCM_SHA512_Ed448;
    private static final SecureRandom RANDOM = new SecureRandom();

    public void testRemoveOtherMemberWithForcedPath()
        throws Exception
    {
        removeOtherMember(true);
    }

    public void testRemoveOtherMemberWithoutForcedPath()
        throws Exception
    {
        removeOtherMember(false);
    }

    private void removeOtherMember(boolean forcePath)
        throws Exception
    {
        Device alice = new Device("alice");
        Device bob = new Device("bob");
        Group group = new Group(Strings.toByteArray("singleton-removal"), SUITE,
            alice.leaf, alice.signingKey, alice.node, new ArrayList<Extension>());
        List<Proposal> proposals = new ArrayList<Proposal>();
        proposals.add(Proposal.add(bob.keyPackage));
        Group.GroupWithMessage joined = group.commit(randomSecret(),
            new Group.CommitOptions(proposals, true, true, null),
            new Group.MessageOptions(), new Group.CommitParameters(Group.NORMAL_COMMIT_PARAMS));
        group = joined.group;
        Group peer = welcome(bob, joined);
        assertTrue(Arrays.equals(group.getEpochAuthenticator(), peer.getEpochAuthenticator()));

        proposals = new ArrayList<Proposal>();
        proposals.add(Proposal.remove(peer.getIndex()));
        Group.GroupWithMessage removed = group.commit(randomSecret(),
            new Group.CommitOptions(proposals, true, forcePath, null),
            new Group.MessageOptions(), new Group.CommitParameters(Group.NORMAL_COMMIT_PARAMS));
        group = removed.group;
        assertEquals(peer.getEpoch() + 1, group.getEpoch());
        assertTrue(group.getGroupInfo(true).groupInfo.verify(SUITE, group.getTree()));

        byte[] aad = Strings.toByteArray("context");
        byte[] plaintext = Strings.toByteArray("after removal");
        MLSMessage message = (MLSMessage)MLSInputStream.decode(
            MLSOutputStream.encode(group.protect(aad, plaintext, 0)), MLSMessage.class);
        try
        {
            peer.unprotect(message);
            fail("removed member accepted a new-epoch message");
        }
        catch (Exception expected)
        {
            // The removed member must not obtain new-epoch application keys.
        }

        Device carol = new Device("carol");
        proposals = new ArrayList<Proposal>();
        proposals.add(Proposal.add(carol.keyPackage));
        Group.GroupWithMessage rejoined = group.commit(randomSecret(),
            new Group.CommitOptions(proposals, true, true, null),
            new Group.MessageOptions(), new Group.CommitParameters(Group.NORMAL_COMMIT_PARAMS));
        Group newPeer = welcome(carol, rejoined);
        assertTrue(Arrays.equals(rejoined.group.getEpochAuthenticator(), newPeer.getEpochAuthenticator()));
        byte[][] received = newPeer.unprotect((MLSMessage)MLSInputStream.decode(
            MLSOutputStream.encode(rejoined.group.protect(aad, plaintext, 0)), MLSMessage.class));
        assertTrue(Arrays.equals(aad, received[0]));
        assertTrue(Arrays.equals(plaintext, received[1]));
    }

    private static Group welcome(Device device, Group.GroupWithMessage joined)
        throws Exception
    {
        return new Group(SUITE.getHPKE().serializePrivateKey(device.init.getPrivate()),
            device.leaf, device.signingKey, device.keyPackage, joined.message.welcome, null,
            new HashMap<Secret, byte[]>(), new HashMap<Group.EpochRef, byte[]>());
    }

    private static Secret randomSecret()
    {
        byte[] bytes = new byte[SUITE.getKDF().getHashLength()];
        RANDOM.nextBytes(bytes);
        return new Secret(bytes);
    }

    private static final class Device
    {
        final AsymmetricCipherKeyPair init = SUITE.getHPKE().generatePrivateKey();
        final AsymmetricCipherKeyPair leaf = SUITE.getHPKE().generatePrivateKey();
        final AsymmetricCipherKeyPair signing = SUITE.generateSignatureKeyPair();
        final byte[] signingKey = SUITE.serializeSignaturePrivateKey(signing.getPrivate());
        final LeafNode node;
        final org.bouncycastle.mls.codec.KeyPackage keyPackage;

        Device(String name)
            throws Exception
        {
            node = new LeafNode(SUITE, SUITE.getHPKE().serializePublicKey(leaf.getPublic()),
                SUITE.serializeSignaturePublicKey(signing.getPublic()),
                Credential.forBasic(Strings.toByteArray(name)), new Capabilities(), new LifeTime(),
                new ArrayList<Extension>(), signingKey);
            keyPackage = new org.bouncycastle.mls.codec.KeyPackage(SUITE,
                SUITE.getHPKE().serializePublicKey(init.getPublic()), node,
                new ArrayList<Extension>(), signingKey);
        }
    }
}
