package org.bouncycastle.mls.test;

import java.util.ArrayList;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.mls.TreeKEM.LeafIndex;
import org.bouncycastle.mls.TreeKEM.LeafNode;
import org.bouncycastle.mls.TreeKEM.LifeTime;
import org.bouncycastle.mls.codec.AuthenticatedContent;
import org.bouncycastle.mls.codec.Capabilities;
import org.bouncycastle.mls.codec.Commit;
import org.bouncycastle.mls.codec.ContentType;
import org.bouncycastle.mls.codec.Credential;
import org.bouncycastle.mls.codec.Extension;
import org.bouncycastle.mls.codec.FramedContent;
import org.bouncycastle.mls.codec.GroupContext;
import org.bouncycastle.mls.codec.MLSMessage;
import org.bouncycastle.mls.codec.MLSOutputStream;
import org.bouncycastle.mls.codec.Proposal;
import org.bouncycastle.mls.codec.PublicMessage;
import org.bouncycastle.mls.codec.Sender;
import org.bouncycastle.mls.codec.WireFormat;
import org.bouncycastle.mls.crypto.MlsCipherSuite;
import org.bouncycastle.mls.protocol.Group;
import org.bouncycastle.util.Strings;

/**
 * Regression tests for the malformed external-join message hardening (finding #13, the missed
 * sibling of commit d1d57913c2 which guarded {@code verifyExternal}).
 * <p>
 * {@code Group.handle(byte[])} unprotects an {@code mls_public_message} and dispatches signature
 * verification purely on sender type via {@code verifyAuth}, <b>before</b> any content-type/path
 * validation in {@code handle(auth, ...)}. For a {@code NEW_MEMBER_COMMIT} /
 * {@code NEW_MEMBER_PROPOSAL} sender the membership-tag check is skipped, so a remote,
 * unauthenticated attacker can drive {@code verifyNewMemberCommit} / {@code verifyNewMemberProposal}
 * with attacker-controlled, optional message fields. A {@code Commit} with an absent
 * {@code UpdatePath} (a legal decode &mdash; {@code readOptional}) or a {@code NEW_MEMBER_PROPOSAL}
 * carrying a non-{@code Add} proposal used to dereference {@code null} and throw a
 * {@code NullPointerException} out of {@code handle()}. After the fix both are rejected with a clean
 * checked {@code Exception}.
 */
public class NewMemberMessageNPETest
    extends TestCase
{
    private static final short SUITE_ID = MlsCipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    public void testMalformedNewMemberCommitIsRejectedNotNPE()
        throws Exception
    {
        MlsCipherSuite suite = MlsCipherSuite.getSuite(SUITE_ID);
        byte[] groupID = Strings.toByteArray("npe-test-group");
        Group group = createFounderGroup(suite, groupID);

        byte[] malformed = buildNewMemberCommitWithNoUpdatePath(suite, groupID);

        try
        {
            group.handle(malformed, null);
            fail("expected a malformed NewMemberCommit to be rejected");
        }
        catch (NullPointerException e)
        {
            fail("NullPointerException leaked from handle() for a malformed NewMemberCommit: " + e);
        }
        catch (Exception e)
        {
            assertEquals("malformed NewMemberCommit", e.getMessage());
        }
    }

    public void testMalformedNewMemberProposalIsRejectedNotNPE()
        throws Exception
    {
        MlsCipherSuite suite = MlsCipherSuite.getSuite(SUITE_ID);
        byte[] groupID = Strings.toByteArray("npe-test-group");
        Group group = createFounderGroup(suite, groupID);

        byte[] malformed = buildNewMemberProposalNonAdd(suite, groupID);

        try
        {
            group.handle(malformed, null);
            fail("expected a malformed NewMemberProposal to be rejected");
        }
        catch (NullPointerException e)
        {
            fail("NullPointerException leaked from handle() for a malformed NewMemberProposal: " + e);
        }
        catch (Exception e)
        {
            assertEquals("malformed NewMemberProposal", e.getMessage());
        }
    }

    // Establishes a single-member group, mirroring MLSClientImpl.createGroupImpl.
    private Group createFounderGroup(MlsCipherSuite suite, byte[] groupID)
        throws Exception
    {
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

    // An mls_public_message from a NEW_MEMBER_COMMIT sender whose Commit has no UpdatePath
    // (absent is a legal decode via readOptional, so updatePath == null on the receiver).
    private byte[] buildNewMemberCommitWithNoUpdatePath(MlsCipherSuite suite, byte[] groupID)
        throws Exception
    {
        Commit commit = new Commit();

        FramedContent content = new FramedContent(
            groupID, 0L, Sender.forNewMemberCommit(), new byte[0], null,
            ContentType.COMMIT, null, commit);

        // The signature is never reached - the null UpdatePath is dereferenced (pre-fix) or the
        // guard fires (post-fix) before auth.verify - so a throwaway signing key is sufficient.
        AsymmetricCipherKeyPair attackerSig = suite.generateSignatureKeyPair();
        byte[] sigSk = suite.serializeSignaturePrivateKey(attackerSig.getPrivate());

        // A NEW_MEMBER_COMMIT TBS embeds the group context, so this must be a valid encoding.
        AuthenticatedContent auth = AuthenticatedContent.sign(
            WireFormat.mls_public_message, content, suite, sigSk, encodeDummyGroupContext(suite, groupID));
        // A COMMIT carries a confirmation_tag on the wire; supply one so the message round-trips.
        auth.setConfirmationTag(new byte[32]);

        return encodePublicMessage(suite, auth);
    }

    // An mls_public_message from a NEW_MEMBER_PROPOSAL sender carrying a non-Add (Remove) proposal,
    // so proposal.getAdd() == null on the receiver.
    private byte[] buildNewMemberProposalNonAdd(MlsCipherSuite suite, byte[] groupID)
        throws Exception
    {
        Proposal proposal = Proposal.remove(new LeafIndex(0));

        FramedContent content = new FramedContent(
            groupID, 0L, Sender.forNewMemberProposal(), new byte[0], null,
            ContentType.PROPOSAL, proposal, null);

        AsymmetricCipherKeyPair attackerSig = suite.generateSignatureKeyPair();
        byte[] sigSk = suite.serializeSignaturePrivateKey(attackerSig.getPrivate());

        // A NEW_MEMBER_PROPOSAL TBS does not embed the group context, so the bytes are ignored.
        AuthenticatedContent auth = AuthenticatedContent.sign(
            WireFormat.mls_public_message, content, suite, sigSk, new byte[0]);

        return encodePublicMessage(suite, auth);
    }

    private byte[] encodePublicMessage(MlsCipherSuite suite, AuthenticatedContent auth)
        throws Exception
    {
        MLSMessage message = new MLSMessage(WireFormat.mls_public_message);
        // For a non-MEMBER sender protect() does not compute a membership tag, so the key/context
        // arguments are unused.
        message.publicMessage = PublicMessage.protect(auth, suite, new byte[0], new byte[0]);
        return MLSOutputStream.encode(message);
    }

    private byte[] encodeDummyGroupContext(MlsCipherSuite suite, byte[] groupID)
        throws Exception
    {
        GroupContext ctx = new GroupContext(
            suite, groupID, 0L, new byte[32], new byte[32], new ArrayList<Extension>());
        return MLSOutputStream.encode(ctx);
    }
}
