package org.bouncycastle.mls.client;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.mls.GroupKeySet;
import org.bouncycastle.mls.KeyScheduleEpoch;
import org.bouncycastle.mls.TranscriptHash;
import org.bouncycastle.mls.TreeKEM.LeafIndex;
import org.bouncycastle.mls.TreeKEM.LeafNode;
import org.bouncycastle.mls.TreeKEM.LeafNodeSource;
import org.bouncycastle.mls.TreeKEM.NodeIndex;
import org.bouncycastle.mls.TreeKEM.TreeKEMPrivateKey;
import org.bouncycastle.mls.TreeKEM.TreeKEMPublicKey;
import org.bouncycastle.mls.TreeSize;
import org.bouncycastle.mls.codec.AuthenticatedContent;
import org.bouncycastle.mls.codec.Capabilities;
import org.bouncycastle.mls.codec.Commit;
import org.bouncycastle.mls.codec.ContentType;
import org.bouncycastle.mls.codec.Credential;
import org.bouncycastle.mls.codec.Extension;
import org.bouncycastle.mls.codec.ExtensionType;
import org.bouncycastle.mls.codec.ExternalSender;
import org.bouncycastle.mls.codec.FramedContent;
import org.bouncycastle.mls.codec.GroupContext;
import org.bouncycastle.mls.codec.GroupInfo;
import org.bouncycastle.mls.codec.GroupSecrets;
import org.bouncycastle.mls.codec.KeyPackage;
import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSMessage;
import org.bouncycastle.mls.codec.MLSOutputStream;
import org.bouncycastle.mls.codec.PSKType;
import org.bouncycastle.mls.codec.PreSharedKeyID;
import org.bouncycastle.mls.codec.PrivateMessage;
import org.bouncycastle.mls.codec.Proposal;
import org.bouncycastle.mls.codec.ProposalOrRef;
import org.bouncycastle.mls.codec.ProposalType;
import org.bouncycastle.mls.codec.ProtocolVersion;
import org.bouncycastle.mls.codec.PublicMessage;
import org.bouncycastle.mls.codec.ResumptionPSKUsage;
import org.bouncycastle.mls.codec.Sender;
import org.bouncycastle.mls.codec.SenderType;
import org.bouncycastle.mls.codec.UpdatePath;
import org.bouncycastle.mls.codec.Welcome;
import org.bouncycastle.mls.codec.WireFormat;
import org.bouncycastle.mls.crypto.CipherSuite;
import org.bouncycastle.mls.crypto.Secret;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.lang.reflect.Array;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class Group
{

    public class GroupWithMessage
    {
        public Group group;
        public MLSMessage message;

        public GroupWithMessage(Group group, MLSMessage message)
        {
            this.group = group;
            this.message = message;
        }
    }
    class Tombstone
    {
        //const
        final byte[] epochAuthenticator;
        final Proposal.ReInit reinit;

        //private
        byte[] priorGroupID;
        long priorEpoch;
        byte[] resumptionPsk;

        public Tombstone(Group group, Proposal.ReInit reinit)
        {
            epochAuthenticator = group.getEpochAuthenticator();
            this.reinit = reinit;
            priorGroupID = group.groupID;
            priorEpoch = group.epoch;
            resumptionPsk = group.keySchedule.resumptionPSK.value();
        }

        public GroupWithMessage createWelcome(AsymmetricCipherKeyPair encSk, byte[] sigSk, LeafNode leafNode, List<KeyPackage> keyPackages, byte[] leafSecret, CommitOptions options) throws Exception
        {
            // Create new empty group with the appropriate PSK
            Group newGroup = new Group(
                    reinit.getGroup_id(),
                    new CipherSuite(reinit.getCipherSuite()),
                    encSk,
                    sigSk,
                    leafNode,
                    reinit.getExtensions()
            );
            newGroup.resumptionPSKs.put(new EpochRef(priorGroupID, priorEpoch), resumptionPsk);

            // Create Add proposals
            List<Proposal> proposals = new ArrayList<>();
            for (KeyPackage kp : keyPackages)
            {
                proposals.add(newGroup.addProposal(kp));
            }

            // Create PSK proposal
            byte[] nonce = new byte[suite.getKDF().getHashLength()];
            SecureRandom random = new SecureRandom();
            random.nextBytes(nonce);
            proposals.add(Proposal.preSharedKey(PreSharedKeyID.resumption(ResumptionPSKUsage.REINIT, priorGroupID, priorEpoch, nonce)));

            // Commit the Add and PSK proposals
            CommitOptions opts = new CommitOptions(
                    proposals,
                    options.inlineTree,
                    options.forcePath,
                    options.leafNodeOptions
            );
            GroupWithMessage gwm = newGroup.commit(new Secret(leafSecret), opts, new MessageOptions(), new CommitParameters(ResumptionPSKUsage.REINIT));
            gwm.message.wireFormat = WireFormat.mls_welcome;
            return gwm;

        }
        public Group handleWelcome(AsymmetricCipherKeyPair initSk, AsymmetricCipherKeyPair encSk, AsymmetricCipherKeyPair sigSk, KeyPackage keyPackage, MLSMessage welcome, TreeKEMPublicKey tree) throws Exception
        {
            Map<EpochRef, byte[]> resumptionPsks = new HashMap<>();
            resumptionPsks.put(new EpochRef(priorGroupID, priorEpoch), resumptionPsk);

            CipherSuite suite = new CipherSuite(welcome.getCipherSuite()); // TODO DONT SERIALIZE KEYS
            Group newGroup = new Group(
                    suite.getHPKE().serializePrivateKey(initSk.getPrivate()),
                    encSk,
                    suite.serializeSignaturePrivateKey(sigSk.getPrivate()),
                    keyPackage,
                    welcome.welcome,
                    tree,
                    new HashMap<>(),
                    resumptionPsks
            );

            if (newGroup.suite.getSuiteId() != reinit.cipherSuite)
            {
                throw new Exception("Attempt to reinit with the wrong ciphersuite");
            }

            if (newGroup.epoch != 1)
            {
                throw new Exception("Reinit not done at the beginning of the group");
            }

            return newGroup;
        }
    }
    class TombstoneWithMessage
        extends Tombstone
    {

        MLSMessage message;
        public TombstoneWithMessage(Group group, Proposal.ReInit reinit, MLSMessage message)
        {
            super(group, reinit);
            this.message = message;
        }
    }

    public static final short NORMAL_COMMIT_PARAMS = 0;
    public static final short EXTERNAL_COMMIT_PARAMS = 1;
    public static final short RESTART_COMMIT_PARAMS = 2;
    public static final short REINIT_COMMIT_PARAMS = 3;
    static public class CommitParameters
    {
        short paramID;
        // External
        KeyPackage joinerKeyPackage;
        Secret forceInitSecret;

        // Restart
        ResumptionPSKUsage allowedUsage;

       public CommitParameters(short paramID)
       {
           this.paramID = paramID;
       }
        public CommitParameters(KeyPackage joinerKeyPackage, Secret forceInitSecret)
        {
            this.paramID = EXTERNAL_COMMIT_PARAMS;
            this.joinerKeyPackage = joinerKeyPackage;
            this.forceInitSecret = forceInitSecret;
        }
        public CommitParameters(short paramID, KeyPackage joinerKeyPackage, Secret forceInitSecret, ResumptionPSKUsage allowedUsage)
        {
            this.paramID = paramID;
            this.joinerKeyPackage = joinerKeyPackage;
            this.forceInitSecret = forceInitSecret;
            this.allowedUsage = allowedUsage;
        }

        public CommitParameters(ResumptionPSKUsage reinit)
        {
            paramID = RESTART_COMMIT_PARAMS;
            allowedUsage = reinit;
        }
    }
    public static class MessageOptions
    {
        boolean encrypt = false;
        byte[] authenticatedData;
        int paddingSize = 0;

        public MessageOptions()
        {
            authenticatedData = new byte[0];
        }

        public MessageOptions(boolean encrypt, byte[] authenticatedData, int paddingSize)
        {
            this.encrypt = encrypt;
            this.authenticatedData = authenticatedData;
            this.paddingSize = paddingSize;
        }
    }
    public static class LeafNodeOptions
    {
        Credential credential;
        Capabilities capabilities;
        List<Extension> extensions;

        public Credential getCredential()
        {
            return credential;
        }

        public Capabilities getCapabilities()
        {
            return capabilities;
        }

        public List<Extension> getExtensions()
        {
            return extensions;
        }

        public LeafNodeOptions()
        {
        }

        public LeafNodeOptions(Credential credential, Capabilities capabilities, List<Extension> extensions)
        {
            this.credential = credential;
            this.capabilities = capabilities;
            this.extensions = extensions;
        }
    }
    public static class CommitOptions
    {
        List<Proposal> extraProposals;
        boolean inlineTree;
        boolean forcePath;
        LeafNodeOptions leafNodeOptions;

        public CommitOptions()
        {
            this.extraProposals = new ArrayList<>();
            this.leafNodeOptions = new LeafNodeOptions();

        }
        public CommitOptions(List<Proposal> extraProposals, boolean inlineTree, boolean forcePath, LeafNodeOptions leafNodeOptions)
        {
            this.extraProposals = extraProposals;
            this.inlineTree = inlineTree;
            this.forcePath = forcePath;
            if (leafNodeOptions == null)
            {
                this.leafNodeOptions = new LeafNodeOptions();
            }
            else
            {
                this.leafNodeOptions = leafNodeOptions;
            }
        }
    }
    class JoinersWithPSKS
    {
        List<LeafIndex> joiners;
        List<KeyScheduleEpoch.PSKWithSecret> psks;

        public JoinersWithPSKS(List<LeafIndex> joiners, List<KeyScheduleEpoch.PSKWithSecret> psks)
        {
            this.psks = psks;
            this.joiners = joiners;
        }
    }
    class EpochRef
    {
        byte[] id;
        long epoch;


        public EpochRef(byte[] id, long epoch)
        {
            this.id = id.clone();
            this.epoch = epoch;
        }

        @Override
        public boolean equals(Object o)
        {
            if (this == o)
            {
                return true;
            }
            if (o == null || getClass() != o.getClass())
            {
                return false;
            }

            EpochRef epochRef = (EpochRef) o;

            if (epoch != epochRef.epoch)
            {
                return false;
            }
            return Arrays.equals(id, epochRef.id);
        }

        @Override
        public int hashCode()
        {
            int result = Arrays.hashCode(id);
            result = 31 * result + (int) (epoch ^ (epoch >>> 32));
            return result;
        }
    }
    Map<Secret, byte[]> externalPSKs;
    private Map<EpochRef, byte[]> resumptionPSKs;
    private long epoch;
    private byte[] groupID;
    public TranscriptHash transcriptHash;
    public ArrayList<Extension> extensions;
    public KeyScheduleEpoch keySchedule;
    public TreeKEMPublicKey tree;
    private TreeKEMPrivateKey treePriv;
    private GroupKeySet keys;
    public CipherSuite suite;
    private LeafIndex index;
    private byte[] identitySk; // TODO: maybe make this AsymmetricCipherKeyPair
//    private ArrayList<CachedProposal> proposalQueue;
    private ArrayList<CachedProposal> pendingProposals;
    private CachedUpdate cachedUpdate;

    public long getEpoch()
    {
        return epoch;
    }

    public byte[] getGroupID()
    {
        return groupID;
    }

    public LeafIndex getIndex()
    {
        return index;
    }

    public MLSMessage getGroupInfo(boolean inlineTree) throws Exception
    {
        GroupInfo groupInfo = new GroupInfo(
                new GroupContext(
                        suite.getSuiteId(),
                        groupID,
                        epoch,
                        tree.getRootHash(),
                        transcriptHash.confirmed,
                        extensions
                ),
                new ArrayList<>(),
                keySchedule.confirmationTag(transcriptHash.confirmed)
        );

        byte[] externalPub = suite.getHPKE().serializePublicKey(keySchedule.getExternalPublicKey());
        MLSOutputStream stream = new MLSOutputStream();
        stream.writeOpaque(externalPub);

        groupInfo.extensions.add(new Extension(ExtensionType.EXTERNAL_PUB, stream.toByteArray()));

        if (inlineTree)
        {
            groupInfo.extensions.add(new Extension(ExtensionType.RATCHET_TREE, MLSOutputStream.encode(tree)));
        }

        groupInfo.sign(tree, index, suite.deserializeSignaturePrivateKey(identitySk));
        MLSMessage msg = new MLSMessage(WireFormat.mls_group_info);
        msg.groupInfo = groupInfo;
        return msg;
    }

    public Group()
    {
    }

    public Group(AsymmetricCipherKeyPair sigSk, GroupInfo groupInfo, TreeKEMPublicKey tree) throws Exception
    {
        this.suite = new CipherSuite(groupInfo.groupContext.ciphersuite);
        this.groupID = groupInfo.groupContext.groupID.clone();
        this.epoch = groupInfo.groupContext.epoch;
        this.tree = TreeKEMPublicKey.clone(importTree(groupInfo.groupContext.treeHash, tree, groupInfo.extensions));
        this.treePriv = new TreeKEMPrivateKey(suite, new LeafIndex(0));// check this should be null
        this.transcriptHash = TranscriptHash.fromConfirmationTag(this.suite, groupInfo.groupContext.confirmedTranscriptHash, groupInfo.confirmationTag);
        this.extensions = new ArrayList<>(groupInfo.groupContext.extensions);
        this.keySchedule = new KeyScheduleEpoch(this.suite);
        this.index = new LeafIndex(0);
        this.identitySk = suite.serializeSignaturePrivateKey(sigSk.getPrivate());
        this.pendingProposals = new ArrayList<>();
        this.resumptionPSKs = new HashMap<>();
        this.externalPSKs = new HashMap<>();
        this.keys = null;

    }
    // Create a new group
    public Group(
            byte[] groupID,
            CipherSuite suite,
            AsymmetricCipherKeyPair encSk,
            byte[] sigSk,
            LeafNode leafNode,
            List<Extension> extensions
    ) throws Exception
    {
        this.suite = suite;
        this.groupID = groupID.clone();
        this.epoch = 0;
        tree = new TreeKEMPublicKey(suite);
        this.transcriptHash = new TranscriptHash(suite);
        this.extensions = new ArrayList<>();
        this.extensions.addAll(extensions);
        this.index = new LeafIndex(0);
        this.identitySk = sigSk.clone();

        this.pendingProposals = new ArrayList<>();
        this.externalPSKs = new HashMap<>();
        this.resumptionPSKs = new HashMap<>();
        //TODO: verify client supports the proposed group extensions

        index = tree.addLeaf(leafNode);
        tree.setHashAll();
        treePriv = TreeKEMPrivateKey.solo(suite, index, encSk);
        if (!treePriv.consistent(tree))
        {
            throw new Exception("LeafNode inconsistent with private key");
        }

        byte[] ctx = MLSOutputStream.encode(getGroupContext());
        keySchedule = KeyScheduleEpoch.forCreator(suite, ctx);
        //TODO DELETE TEST
//        keySchedule = KeyScheduleEpoch.forCreatorTEST(suite, ctx, Hex.decode("16f4327dd927663cff04663762adb7c4ac48885c07e3d290093c5f72f3a7c275"));
//        System.out.println("initSecret: " + Hex.toHexString(keySchedule.initSecret.value()));
//        System.out.println("senderDataSecret: " + Hex.toHexString(keySchedule.senderDataSecret.value()));
//        System.out.println("exporterSecret: " + Hex.toHexString(keySchedule.exporterSecret.value()));
//        System.out.println("confirmationKey: " + Hex.toHexString(keySchedule.confirmationKey.value()));
//        System.out.println("membershipKey: " + Hex.toHexString(keySchedule.membershipKey.value()));
//        System.out.println("resumptionPSK: " + Hex.toHexString(keySchedule.resumptionPSK.value()));
//        System.out.println("epochAuthenticator: " + Hex.toHexString(keySchedule.epochAuthenticator.value()));
//        System.out.println("encryptionSecret: " + Hex.toHexString(keySchedule.encryptionSecret.value()));
//        System.out.println("externalSecret: " + Hex.toHexString(keySchedule.externalSecret.value()));
//        System.out.println("joinerSecret: " + Hex.toHexString(keySchedule.joinerSecret.value()));

        this.keys = keySchedule.getEncryptionKeys(tree.size);

        // Update the interim transcript hash with a virtual confirmation tag
        transcriptHash.updateInterim(keySchedule.confirmationTag(transcriptHash.confirmed));
    }

    // Creates a group from a welcome message
    /**
     *
     * @param initSk HPKE private key
     * @param leafSk HPKE private key for leaf node
     * @param sigSk signature private key
     * @param keyPackage key package
     * @param welcome welcome
     * @param treeIn public kem tree (optional)
     * @param externalPsks map of external psks
     * @param resumptionPsks map of resumptions psks
     * @throws Exception
     */
    public Group(
            byte[] initSk,
            AsymmetricCipherKeyPair leafSk,
            byte[] sigSk,
            KeyPackage keyPackage,
            Welcome welcome,
            TreeKEMPublicKey treeIn,
            Map<Secret, byte[]> externalPsks,
            Map<EpochRef, byte[]> resumptionPsks
    )
            throws Exception
    {
        pendingProposals = new ArrayList<>();
        suite = new CipherSuite(welcome.cipher_suite);
        epoch = 0;
        transcriptHash = new TranscriptHash(suite);
        identitySk = sigSk;
        externalPSKs = new HashMap<>();
        externalPSKs.putAll(externalPsks);
        this.resumptionPSKs = new HashMap<>();
        this.resumptionPSKs.putAll(resumptionPsks);

        int kpi = welcome.find(keyPackage);
        if (kpi == -1)
        {
            throw new Exception("Welcome not intended for key package");
        }

        if (keyPackage.cipher_suite != welcome.cipher_suite)
        {
            throw new Exception("Ciphersuite mismatch");
        }

        // Decrypting GroupSecrets and checking PSKs
        GroupSecrets secrets = welcome.decryptSecrets(kpi, initSk);
        List<KeyScheduleEpoch.PSKWithSecret> psks = resolve(secrets.psks);

        // Decrypting GroupInfo
        GroupInfo groupInfo = welcome.decrypt(secrets.joiner_secret, psks);
        if (groupInfo.groupContext.ciphersuite != suite.getSuiteId())
        {
            throw new Exception("GroupInfo and Welcome ciphersuites disagree");
        }

        // Get tree from argument or from extension
        tree = TreeKEMPublicKey.clone(importTree(groupInfo.groupContext.treeHash, treeIn, groupInfo.extensions));

        // Verifying GroupInfo signature
        if (!groupInfo.verify(suite, tree))
        {
            throw new Exception("Invalid GroupInfo");
        }

        // Set the GroupSecrets and GroupInfo
        epoch = groupInfo.groupContext.epoch;
        groupID = groupInfo.groupContext.groupID;

        transcriptHash.confirmed = groupInfo.groupContext.confirmedTranscriptHash.clone();
        transcriptHash.updateInterim(groupInfo.confirmationTag);

        extensions = new ArrayList<>(); // TODO: Check to clone?
        extensions.addAll(groupInfo.groupContext.extensions);

        // Create the TreeKEMPrivateKey
        int i = tree.find(keyPackage.leaf_node);
        if (i == -1)
        {
            throw new Exception("New joiner not in tree");
        }
        index = new LeafIndex(i);

        NodeIndex ancestor = index.commonAncestor(groupInfo.signer);
        Secret pathSecret;
        if (secrets.path_secret != null)
        {
            pathSecret = new Secret(secrets.path_secret.path_secret);
        }
        else
        {
            pathSecret = new Secret(new byte[0]);
        }
        treePriv = TreeKEMPrivateKey.joiner(tree, index, leafSk, ancestor, pathSecret);

        // Ratchet forward into current epoch
        byte[] groupCtx = MLSOutputStream.encode(getGroupContext());

        keySchedule = KeyScheduleEpoch.joiner(suite, secrets.joiner_secret, psks, groupCtx);
        keys = keySchedule.getEncryptionKeys(tree.size);

        // Verify confirmation tag
        byte[] confirmationTag = keySchedule.confirmationTag(transcriptHash.confirmed);
        if (!Arrays.equals(confirmationTag, groupInfo.confirmationTag))
        {
            throw new Exception("Confirmation failed to verify");
        }
    }

    public Group handle(byte[] mlsMessageBytes, Group cachedGroup) throws Exception
    {
        return handle(mlsMessageBytes, cachedGroup, null);
    }
    public Group handle(byte[] mlsMessageBytes, Group cachedGroup, CommitParameters expectedParams) throws Exception
    {
        MLSMessage msg = (MLSMessage) MLSInputStream.decode(mlsMessageBytes, MLSMessage.class);
        if (msg.version != ProtocolVersion.mls10) //TODO: do check in MLSMessage?
        {
            throw new Exception("Unsupported version");
        }

        AuthenticatedContent auth;
        switch (msg.wireFormat)
        {
            case mls_public_message:
                auth = msg.publicMessage.unprotect(suite, keySchedule.membershipKey, getGroupContext());
                if (auth == null)//TODO: remove this?
                {
                    throw new Exception("Membership tag failed to verify");
                }
                break;
            case mls_private_message:
                auth = msg.privateMessage.unprotect(suite, keys, keySchedule.senderDataSecret.value());
                if (auth == null)
                {
                    throw new Exception("PrivateMessage decryption failure");
                }
                break;
            default:
                throw new Exception("Invalid wire format");
        }
        if (!verifyAuth(auth))
        {
            throw new Exception("Message signature failed to verify");
        }
        return handle(auth, cachedGroup, expectedParams);
    }


    public Group handle(AuthenticatedContent auth, Group cachedGroup, CommitParameters expectedParams) throws Exception
    {
        // Validate the GroupContent
        FramedContent content = auth.content;
        if (!Arrays.equals(content.group_id, groupID))
        {
            throw new Exception("GroupID mismatch");
        }

        if (content.epoch != epoch)
        {
            throw new Exception("epoch mismatch");
        }

        // Dispatch on content type
        switch (content.getContentType())
        {
            case PROPOSAL:
                // Proposals get queued, do not result in a state transition
                cacheProposal(auth);
                return null;
            case COMMIT:
                // Commits are handled in the remainder of this method
                break;
            default:
                // Any other content type in this method is an error
                throw new Exception("Invalid content type");
        }

        switch (content.sender.senderType)
        {
            case MEMBER:
            case NEW_MEMBER_COMMIT:
                break;
            default:
                throw new Exception("Invalid commit sender type");
        }

        LeafIndex sender = null;
        if (content.sender.senderType == SenderType.MEMBER)
        {
            sender = content.sender.sender;
        }

        if (index.equals(sender))
        {
            if (cachedGroup != null)
            {
                // Verify that the cached state is a plausible successor to this state
                if (!Arrays.equals(cachedGroup.groupID, groupID) || cachedGroup.epoch != epoch + 1 || !cachedGroup.index.equals(index))
                {
                    throw new Exception("Invalid successor state");
                }

                return cachedGroup;
            }

            throw new Exception("Handle own commits with caching");
        }

        // Apply the commit
        Commit commit = content.commit;
        List<CachedProposal> proposals = mustResolve(commit.proposals, sender);

        CommitParameters params = inferCommitType(sender, proposals, expectedParams);
        boolean externalcommit = params.paramID == EXTERNAL_COMMIT_PARAMS;
//        System.out.println("Params GOT: " + params.paramID);

        // Check that a path is present when required
        if (pathRequired(proposals) && commit.updatePath == null)
        {
            throw new Exception("Path required but not present");
        }

        // Apply the proposals
        Group next = successor();
        JoinersWithPSKS joinersWithPSKS = next.apply(proposals);

        // If this is an external commit, add the joiner to the tree and note the
        // location where they were added.  Also, compute the "externally forced"
        // value that we will use for the init_secret (as opposed to the init_secret
        // from the key schedule).

        byte[] forceInitSecret = null;
        LeafIndex senderLocation = new LeafIndex(0);
        if (!externalcommit)
        {
            senderLocation = sender;
        }
        else
        {
//            senderLocation = next.tree.allocateLeaf();
            // Add the joiner
            UpdatePath path = commit.updatePath.clone();
            senderLocation = next.tree.addLeaf(path.leaf_node);
//            senderLocation = next.tree.addLeaf(commit.updatePath.leaf_node);

            // Extract the forced init secret
            byte[] kemOut = commit.validityExternal();
            if (kemOut == null)
            {
                throw new Exception("Invalid external commit");
            }
            forceInitSecret = keySchedule.receiveExternalInit(kemOut);
        }

        // Decapsulate and apply the UpdatePath, if provided
        byte[] commitSecret = new byte[suite.getKDF().getHashLength()];
        if (commit.updatePath != null)
        {
            UpdatePath path = commit.updatePath.clone();
            if (!validateLeafNode(path.leaf_node, LeafNodeSource.COMMIT, senderLocation))
            {
                throw new Exception("Commit path has invalid leaf node");
            }

//            next.tree.dump();
            if (!next.tree.verifyParentHash(senderLocation, path))
            {
                throw new Exception("Commit path has invalid parent hash");
            }

            next.tree.merge(senderLocation, path);
//            next.tree.dump();

            byte[] ctx = MLSOutputStream.encode(new GroupContext(
                    next.suite.getSuiteId(),
                    next.groupID,
                    next.epoch + 1,
                    next.tree.getRootHash(),
                    next.transcriptHash.confirmed,
                    next.extensions
            ));
//            next.treePriv.dump();
            next.treePriv.decap(
                    senderLocation,
                    next.tree,
                    ctx,
                    path,
                    joinersWithPSKS.joiners
            );
            commitSecret = next.treePriv.updateSecret.value().clone();
        }
        // Update the transcripts and advance the key schedule

        next.transcriptHash.update(auth);
        next.epoch += 1;
        next.updateEpochSecrets(commitSecret, joinersWithPSKS.psks, forceInitSecret);

        // Verify the confirmation MAC
        byte[] confirmationTag = next.keySchedule.confirmationTag(next.transcriptHash.confirmed);

        if (!Arrays.equals(auth.getConfirmationTag(), confirmationTag))
        {
            throw new Exception("Confirmation failed to verify");
        }

        return next;

    }

    private CommitParameters inferCommitType(LeafIndex sender, List<CachedProposal> proposals, CommitParameters expectedParams) throws Exception
    {
        // If an expected type was provided, validate against it
        if(expectedParams != null)
        {
            boolean specifically = false;
            switch (expectedParams.paramID)
            {
                case NORMAL_COMMIT_PARAMS:
                    specifically = (sender != null) && validateNormalCachedProposals(proposals, sender);
                    break;
                case EXTERNAL_COMMIT_PARAMS:
                    specifically = (sender == null) && validateExternalCachedProposals(proposals);
                    break;
                case RESTART_COMMIT_PARAMS:
                    specifically = (sender != null) && validateRestartCachedProposals(proposals, expectedParams.allowedUsage);
                    break;
                case REINIT_COMMIT_PARAMS:
                    specifically = (sender != null) && validateReInitCachedProposals(proposals);
                    break;
            }
            if (!specifically)
            {
                throw new Exception("Invalid proposal list");
            }

            return expectedParams;
        }

        // Otherwise, check to see if this is a valid external or normal commit
        if ((sender == null) && validateExternalCachedProposals(proposals))
        {
            return new CommitParameters(EXTERNAL_COMMIT_PARAMS);
        }

        if ((sender != null) && validateNormalCachedProposals(proposals, sender))
        {
            return new CommitParameters(NORMAL_COMMIT_PARAMS);
        }

        throw new Exception("Invalid proposal list");

    }

    public GroupWithMessage createBranch(byte[] groupID, AsymmetricCipherKeyPair encryptionKeyPair, AsymmetricCipherKeyPair signatureKeyPair, LeafNode leafNode, List<Extension> extList, List<KeyPackage> keyPackages, byte[] leafSecret, CommitOptions commitOptions) throws Exception
    {
        // Create a new empty group with the appropriate PSK
        Group newGroup = new Group(groupID, suite, encryptionKeyPair,suite.serializeSignaturePrivateKey(signatureKeyPair.getPrivate()), leafNode, extensions);
        newGroup.resumptionPSKs.put(new EpochRef(this.groupID, this.epoch), this.keySchedule.resumptionPSK.value().clone());

        // Create Add proposals
        List<Proposal> proposals = new ArrayList<>();
        for (KeyPackage kp : keyPackages)
        {
            proposals.add(newGroup.addProposal(kp));
        }

        // Create PSK Proposal
        byte[] nonce = new byte[suite.getKDF().getHashLength()];
        SecureRandom random = new SecureRandom();
        random.nextBytes(nonce);
        proposals.add(Proposal.preSharedKey(PreSharedKeyID.resumption(ResumptionPSKUsage.BRANCH, this.groupID, this.epoch, nonce)));

        // Commit the Add and PSK proposals
        CommitOptions opts = new CommitOptions(
                proposals,
                commitOptions.inlineTree,
                commitOptions.forcePath,
                commitOptions.leafNodeOptions
        );
        GroupWithMessage gwm = newGroup.commit(new Secret(leafSecret), opts, new MessageOptions(), new CommitParameters(ResumptionPSKUsage.BRANCH));
        gwm.message.wireFormat = WireFormat.mls_welcome;
        return gwm;
    }

    public Group handleBranch(AsymmetricCipherKeyPair initSk, AsymmetricCipherKeyPair encSk, AsymmetricCipherKeyPair sigSk, KeyPackage keyPackage, MLSMessage welcome, TreeKEMPublicKey tree) throws Exception
    {
        Map<EpochRef, byte[]> resumptionPsks = new HashMap<>();
        resumptionPsks.put(new EpochRef(this.groupID, this.epoch), this.keySchedule.resumptionPSK.value().clone());

        Group branchGroup = new Group(
                suite.getHPKE().serializePrivateKey(initSk.getPrivate()),
                encSk,
                suite.serializeSignaturePrivateKey(sigSk.getPrivate()),
                keyPackage,
                welcome.welcome,
                tree,
                new HashMap<>(),
                resumptionPsks
        );

        if (branchGroup.suite.getSuiteId() != suite.getSuiteId())
        {
            throw new Exception("Attempt to branch with a different ciphersuite");
        }
        if (branchGroup.epoch != 1)
        {
            throw new Exception("Branch not done at the beginning of the group");
        }

        return branchGroup;
    }


    public Tombstone handleReinitCommit(MLSMessage commitMessage) throws Exception
    {
        // Verify the signature and process the commit
        AuthenticatedContent auth = unprotectToContentAuth(commitMessage);
        if (!verifyAuth(auth))
        {
            throw new Exception("Message signature failed to verify");
        }

        Group newGroup = handle(auth, null, new CommitParameters(REINIT_COMMIT_PARAMS));

        // Extract the reinit and create the tombstone
        Commit commit = auth.content.commit;
        List<CachedProposal> proposals = mustResolve(commit.proposals, null);
        if (!validateReinitProposals(proposals))
        {
            throw new Exception("Invalid proposals for reinit");
        }

        CachedProposal reinitProposal = proposals.get(0);
        return new Tombstone(newGroup, reinitProposal.proposal.reInit);
    }


    //TODO DELETE TEST
//    public static ArrayList<byte[]> TESTEXTERNALJOIN = new ArrayList<>(java.util.Arrays.asList(
//            Hex.decode("8533764049808656ae660d3215ab3801c760af269e2b80823d1ebb7f37b89350"),// end
//            Hex.decode("a347640b9b6b7afb7dfa3bdb1b75c2282ec85374e0291e0a5165a515508cd009"),//force_init_secret
//            Hex.decode("314568cefcc8d759ee28688f5aaf615b1b9dcbed9d7ee176589c0bfde26aab21"),// end
//            Hex.decode("bfc0025718870a78d0bdc68e08b40fd72bea0c18584b3b11c74a55c78ffef2dd") //force_init_secret
//    ));

    public static GroupWithMessage externalJoin(Secret leafSecret,
                             AsymmetricCipherKeyPair sigSk,
                             KeyPackage keyPackage,
                             GroupInfo groupInfo,
                             TreeKEMPublicKey tree,
                             MessageOptions msgOptions,
                             LeafIndex removePrior,
                             Map<Secret, byte[]> psks)
            throws Exception
    {
//        System.out.println("group_info.group_context.confirmed_transcript_hash: " + Hex.toHexString(groupInfo.groupContext.confirmedTranscriptHash));
//        System.out.println("group_info.confirmation_tag: " + Hex.toHexString(groupInfo.confirmationTag));
        // Create a preliminary group
        Group initialGroup = new Group(sigSk, groupInfo, tree);
//        System.out.println("initialGroup interim: " + Hex.toHexString(initialGroup.transcriptHash.interim));
//        System.out.println("initialGroup confirmed: " + Hex.toHexString(initialGroup.transcriptHash.confirmed));

        CipherSuite suite = new CipherSuite(keyPackage.cipher_suite);

        // Look up the external public key for the group
        byte[] extPub = null;
        for (Extension ext : groupInfo.extensions)
        {
            if (extPub != null)
            {
                break;
            }
            extPub = ext.getExternalPub();
        }
        if (extPub == null)
        {
            throw new Exception("No external pub in GroupInfo");
        }

        // Insert an ExternalInit proposal
        CommitOptions options = new CommitOptions();
        KeyScheduleEpoch.ExternalInitParams extParams = new KeyScheduleEpoch.ExternalInitParams(
                suite, suite.getHPKE().deserializePublicKey(extPub));

        //TODO DELETE TEST
//        extParams.kemOutput = TESTEXTERNALJOIN.get(0); TESTEXTERNALJOIN.remove(0);
//        extParams.initSecret = new Secret (TESTEXTERNALJOIN.get(0)); TESTEXTERNALJOIN.remove(0);
//        System.out.println("ext.kem_out: " + Hex.toHexString(extParams.getKEMOutput()));
//        System.out.println("ext.init_secret: " + Hex.toHexString(extParams.getInitSecret().value()));

        options.extraProposals.add(Proposal.externalInit(extParams.getKEMOutput()));

        // Evict a prior appearance if required
        if (removePrior != null) {
            Proposal remove = initialGroup.removeProposal(removePrior);
            options.extraProposals.add(remove);
        }

        // Inject PKSs
        for (Secret id : psks.keySet())
        {
            initialGroup.externalPSKs.put(id, psks.get(id));
            options.extraProposals.add(initialGroup.preSharedKeyProposal(id));
        }

        // Use the preliminary state to create a commit and advance to a real state
        CommitParameters commitParameters = new CommitParameters(keyPackage, extParams.getInitSecret());
        GroupWithMessage gwm = initialGroup.commit(leafSecret, options, msgOptions, commitParameters);
        gwm.message.welcome = null;
        return gwm;
    }

    public GroupWithMessage commit(Secret leafSecret, CommitOptions commitOptions, MessageOptions msgOptions, CommitParameters params) throws Exception
    {
//        System.out.println();
        Commit commit = new Commit();
        List<KeyPackage> joiners = new ArrayList<>();
        for (CachedProposal cached : pendingProposals)
        {
            if (cached.proposal.getProposalType() == ProposalType.ADD)
            {
                joiners.add(cached.proposal.add.keyPackage);
            }

            commit.proposals.add(ProposalOrRef.forRef(cached.proposalRef));
        }

        // add the extra proposals to those we had cached
        if (commitOptions != null)
        {
            for (Proposal p : commitOptions.extraProposals)
            {
                if (p.getProposalType() == ProposalType.ADD)
                {
                    joiners.add(p.add.keyPackage);
                }

                commit.proposals.add(ProposalOrRef.forProposal(p));
            }
        }

        // for external commit insert an external init proposal
        byte[] forceInitSecret = null;
        if (params.paramID == EXTERNAL_COMMIT_PARAMS)
        {
            forceInitSecret = params.forceInitSecret.value().clone();
        }

        // Apply proposals
        Group next = successor();

        List<CachedProposal> proposals = mustResolve(commit.proposals, index); // check should just send index.value()
        if (!validateCachedProposals(proposals, index, params))
        {
            throw new Exception("Invalid proposal list");
        }

        JoinersWithPSKS joinersWithpsks = next.apply(proposals);

//        System.out.println("commitParams: " + params.paramID);
        if (params.paramID == EXTERNAL_COMMIT_PARAMS)
        {
            next.index = next.tree.addLeaf(params.joinerKeyPackage.leaf_node);
        }

        // If this is an external commit, indicate it in the sender field
        Sender sender = Sender.forMember(index);
        if (params.paramID == EXTERNAL_COMMIT_PARAMS)
        {
            sender = Sender.forNewMemberCommit();
        }

        // KEM new entropy to the group and the new joiners
        Secret commitSecret = Secret.zero(suite);
        List<Secret> pathSecrets = new ArrayList<>();
        for (int i = 0; i < joinersWithpsks.joiners.size(); i++)
        {
            pathSecrets.add(null);
        }
        boolean forcePath = (commitOptions != null) && commitOptions.forcePath;
        if (forcePath || pathRequired(proposals))
        {
            LeafNodeOptions leafNodeOptions = new LeafNodeOptions();
            if (commitOptions != null)
            {
                leafNodeOptions = commitOptions.leafNodeOptions;
            }
            TreeKEMPrivateKey newPriv = next.tree.update(next.index, leafSecret, next.groupID, identitySk, leafNodeOptions);
            GroupContext ctx = new GroupContext(
                    next.suite.getSuiteId(),
                    next.groupID,
                    next.epoch + 1,
                    next.tree.getRootHash(),
                    next.transcriptHash.confirmed,
                    next.extensions
            );
            byte[] ctxBytes = MLSOutputStream.encode(ctx);
            UpdatePath path = next.tree.encap(newPriv, ctxBytes, joinersWithpsks.joiners);

            next.treePriv = newPriv;
            commit.updatePath = path;
            commitSecret = newPriv.updateSecret;

            for (int i = 0; i < joinersWithpsks.joiners.size(); i++)
            {
                pathSecrets.set(i, newPriv.getSharedPathSecret(joinersWithpsks.joiners.get(i)));
            }
            next.tree.setHashAll();
        }

        // Create the Commit message and advance the transcripts / key schedule
        AuthenticatedContent commitContentAuth = sign(sender, commit, msgOptions.authenticatedData, msgOptions.encrypt);

//        System.out.println("transcriptHash.interim: " + Hex.toHexString(next.transcriptHash.interim));
//        System.out.println("transcriptHash.confirmed: " + Hex.toHexString(next.transcriptHash.confirmed));
        next.transcriptHash.updateConfirmed(commitContentAuth);
        next.epoch += 1;

//        System.out.println("transcriptHash.interim: " + Hex.toHexString(next.transcriptHash.interim));
//        System.out.println("transcriptHash.confirmed: " + Hex.toHexString(next.transcriptHash.confirmed));

        next.updateEpochSecrets(commitSecret.value(), joinersWithpsks.psks, forceInitSecret);

        byte[] confirmationTag = next.keySchedule.confirmationTag(next.transcriptHash.confirmed);
//        System.out.println("confirmationTag: " + Hex.toHexString(confirmationTag));
        commitContentAuth.setConfirmationTag(confirmationTag);

        next.transcriptHash.updateInterim(commitContentAuth);

        MLSMessage commitMessage = protect(commitContentAuth, msgOptions.paddingSize);

        // Complete the GroupInfo and form the Welcome
        next.tree.setHashAll();
        GroupInfo groupInfo = new GroupInfo(
                new GroupContext(
                        next.suite.getSuiteId(),
                        next.groupID,
                        next.epoch,
                        next.tree.getRootHash(),
                        next.transcriptHash.confirmed,
                        next.extensions
                ),
                new ArrayList<>(),
                confirmationTag
        );
        if (commitOptions != null && commitOptions.inlineTree)
        {
            groupInfo.extensions.add(new Extension(ExtensionType.RATCHET_TREE, MLSOutputStream.encode(next.tree)));
        }
        groupInfo.sign(next.tree, next.index, suite.deserializeSignaturePrivateKey(next.identitySk));


        //TODO: should have a way to retrieve joiner secret from key schedule
        Welcome welcome = new Welcome(suite,
                next.keySchedule.getJoinerSecret().value(),
                joinersWithpsks.psks,
                MLSOutputStream.encode(groupInfo));

        for (int i = 0; i < joiners.size(); i++)
        {
            welcome.encrypt(joiners.get(i), pathSecrets.get(i));
        }

//        this.replace(next); //TODO: return instead of replace
        //TODO: separate welcome and commit message
        commitMessage.welcome = welcome;
        return new GroupWithMessage(next, commitMessage);
    }

    public TombstoneWithMessage reinitCommit(byte[] leafSecret, CommitOptions commitOptions, MessageOptions messageOptions) throws Exception
    {
        Proposal reinitProposal = null;
        if (pendingProposals.size() == 1)
        {
            reinitProposal = pendingProposals.get(0).proposal;
        }
        else if (commitOptions != null && commitOptions.extraProposals.size() == 1)
        {
            reinitProposal = commitOptions.extraProposals.get(0);
        }
        else
        {
            throw new Exception("Illegal proposals for reinitialization");
        }

        Proposal.ReInit reinit = reinitProposal.reInit;

        // Create the Commit
        GroupWithMessage gwm = commit(new Secret(leafSecret), commitOptions, messageOptions, new CommitParameters(REINIT_COMMIT_PARAMS));
        gwm.message.welcome = null;
        return new TombstoneWithMessage(gwm.group, reinit, gwm.message);
    }

    static public MLSMessage newMemberAdd(byte[] groupID, long epoch, KeyPackage newMember, AsymmetricCipherKeyPair sigSk) throws Exception
    {
        //TODO: check if null should be new byte[0] instead
        CipherSuite suite = new CipherSuite(newMember.cipher_suite);
        Proposal proposal = Proposal.add(newMember);
        FramedContent content = FramedContent.proposal(
                groupID,
                epoch,
                Sender.forNewMemberProposal(),
                new byte[0],
                MLSOutputStream.encode(proposal)
        );
        AuthenticatedContent contentAuth = AuthenticatedContent.sign(
                WireFormat.mls_public_message,
                content,
                suite,
                suite.serializeSignaturePrivateKey(sigSk.getPrivate()),
                null
        );

        MLSMessage message = new MLSMessage(WireFormat.mls_public_message);
        message.publicMessage = PublicMessage.protect(contentAuth, suite, new byte[0], new byte[0]);
        return message;
    }

    public MLSMessage protect(byte[] applicationData, byte[] pt, int paddingSize) throws Exception
    {
        Group.MessageOptions msgOptions = new Group.MessageOptions(true, applicationData, paddingSize);

        AuthenticatedContent contentAuth = sign(
                Sender.forMember(index),
                pt,
                msgOptions.authenticatedData,
                msgOptions.encrypt
        );
        return protect(contentAuth, msgOptions.paddingSize);
    }
    public byte[][] unprotect(MLSMessage ct) throws Exception
    {
        AuthenticatedContent auth = unprotectToContentAuth(ct);
        if (!verifyAuth(auth))
        {
            throw new Exception("Message signature failed to verify");
        }

        if(auth.content.getContentType() != ContentType.APPLICATION)
        {
            throw new Exception("Unprotected of handshake message");
        }

        if (auth.wireFormat != WireFormat.mls_private_message)
        {
            throw new Exception("Application data not sent as PrivateMessage");
        }
        byte[][] authAndContent = new byte[2][];
        authAndContent[0] = auth.content.getAuthenticated_data();
        authAndContent[1] = auth.content.getContentBytes();
        return authAndContent;
    }

    private boolean verifyAuth(AuthenticatedContent auth) throws Exception
    {
        switch (auth.content.sender.senderType)
        {
            case MEMBER:
                return verifyInternal(auth);
            case EXTERNAL:
                return verifyExternal(auth);
            case NEW_MEMBER_PROPOSAL:
                return verifyNewMemberProposal(auth);
            case NEW_MEMBER_COMMIT:
                return verifyNewMemberCommit(auth);
            default:
                throw new Exception("Invalid sender type");
        }
    }

    private boolean verifyInternal(AuthenticatedContent auth) throws Exception
    {
        LeafNode leaf = tree.getLeafNode(auth.content.sender.sender);
        if (leaf == null)
        {
            throw new Exception("Signature from blank node");
        }
        return auth.verify(suite, leaf.signature_key, MLSOutputStream.encode(getGroupContext()));
    }

    private boolean verifyExternal(AuthenticatedContent auth) throws Exception
    {
        Sender extSender = auth.content.sender;
        Extension sendersExt = null;
        for (Extension ext : extensions)
        {
            if (ext.extensionType == ExtensionType.EXTERNAL_SENDERS)
            {
                sendersExt = ext;
            }
        }
        List<ExternalSender> senders = sendersExt.getSenders();

        return auth.verify(suite,
                senders.get(extSender.sender_index).signatureKey,
                MLSOutputStream.encode(getGroupContext()));
    }

    private boolean verifyNewMemberProposal(AuthenticatedContent auth) throws Exception
    {
        Proposal proposal = auth.content.proposal;
        Proposal.Add add = proposal.add;
        byte[] pub = add.keyPackage.leaf_node.signature_key;
        return auth.verify(suite, pub, MLSOutputStream.encode(getGroupContext()));
    }

    private boolean verifyNewMemberCommit(AuthenticatedContent auth) throws Exception
    {
        Commit commit = auth.content.commit;
        UpdatePath path = commit.updatePath;
        byte[] pub = path.leaf_node.signature_key;
        return auth.verify(suite, pub, MLSOutputStream.encode(getGroupContext()));
    }

    private AuthenticatedContent unprotectToContentAuth(MLSMessage msg) throws Exception
    {
        if (msg.version != ProtocolVersion.mls10)
        {
            throw new Exception("Unsupported version");
        }
        AuthenticatedContent auth = null;
        switch (msg.wireFormat)
        {
            case mls_public_message:
                auth = msg.publicMessage.unprotect(suite, keySchedule.membershipKey, getGroupContext());
                if (auth == null)
                {
                    throw new Exception("Membership tag failed to verify");
                }
                break;
            case mls_private_message:
                auth = msg.privateMessage.unprotect(suite, keys, keySchedule.senderDataSecret.value());
                if (auth == null)
                {
                    throw new Exception("PrivateMessage decryption failure");
                }
                break;
            case mls_welcome:
            case mls_group_info:
            case mls_key_package:
                throw new Exception("Invalid wire format");
        }
        return auth;
    }
    public MLSMessage add(KeyPackage keyPackage, MessageOptions msgOptions) throws Exception
    {
        AuthenticatedContent contentAuth = sign(
                Sender.forMember(index),
                addProposal(keyPackage),
                msgOptions.authenticatedData,
                msgOptions.encrypt
        );
//        System.out.println(Hex.toHexString(MLSOutputStream.encode(contentAuth)));
        return protect(contentAuth, msgOptions.paddingSize);
    }
    public MLSMessage update(Proposal update, MessageOptions msgOptions) throws Exception
    {
        AuthenticatedContent contentAuth = sign(
                Sender.forMember(index),
                update,
                msgOptions.authenticatedData,
                msgOptions.encrypt
        );
        return protect(contentAuth, msgOptions.paddingSize);
    }
    public MLSMessage groupContextExtensions(List<Extension> extensions, MessageOptions msgOptions) throws Exception
    {
        if (!extensionsSupported(extensions))
        {
            throw new Exception("Unsupported extensions");
        }
        AuthenticatedContent contentAuth = sign(
                Sender.forMember(index),
                Proposal.groupContextExtensions(extensions),
                msgOptions.authenticatedData,
                msgOptions.encrypt
        );
        return protect(contentAuth, msgOptions.paddingSize);
    }
    public MLSMessage remove(LeafIndex removeIndex, MessageOptions msgOptions) throws Exception
    {
        // leaf for roster
        Proposal remove = Proposal.remove(leafForRoster(removeIndex));

        AuthenticatedContent contentAuth = sign(
                Sender.forMember(index),
                remove,
                msgOptions.authenticatedData,
                msgOptions.encrypt
        );
        return protect(contentAuth, msgOptions.paddingSize);
    }


    public MLSMessage reinit(byte[] groupID, ProtocolVersion version, CipherSuite suite, List<Extension> extList, MessageOptions msgOptions) throws Exception
    {
        // reinitProposal
        Proposal reinit = Proposal.reInit(groupID, version, suite.getSuiteId(), extList);

        AuthenticatedContent contentAuth = sign(
                Sender.forMember(index),
                reinit,
                msgOptions.authenticatedData,
                msgOptions.encrypt
        );

        return protect(contentAuth, msgOptions.paddingSize);
    }

    public MLSMessage preSharedKey(byte[] externalPskId, MessageOptions msgOptions) throws Exception
    {
        if (!externalPSKs.containsKey(new Secret(externalPskId)))
        {
            throw new Exception("Unknown PSK");
        }
        SecureRandom random = new SecureRandom();
        byte[] nonce = new byte[suite.getKDF().getHashLength()];
        random.nextBytes(nonce);
        PreSharedKeyID pskId = PreSharedKeyID.external(externalPskId, nonce);

        AuthenticatedContent contentAuth = sign(
                Sender.forMember(index),
                Proposal.preSharedKey(pskId),
                msgOptions.authenticatedData,
                msgOptions.encrypt
        );
        return protect(contentAuth, msgOptions.paddingSize);
    }
    public MLSMessage preSharedKey(byte[] groupID, long epoch, MessageOptions msgOptions) throws Exception
    {
        if (epoch != this.epoch && !resumptionPSKs.containsKey(new EpochRef(groupID, epoch)))
        {
            throw new Exception("Unknown PSK");
        }
        SecureRandom random = new SecureRandom();
        byte[] nonce = new byte[suite.getKDF().getHashLength()];
        random.nextBytes(nonce);
        PreSharedKeyID pskId = PreSharedKeyID.resumption(ResumptionPSKUsage.APPLICATION, groupID, epoch, nonce);

        AuthenticatedContent contentAuth = sign(
                Sender.forMember(index),
                Proposal.preSharedKey(pskId),
                msgOptions.authenticatedData,
                msgOptions.encrypt
        );
        return protect(contentAuth, msgOptions.paddingSize);
    }

    private LeafIndex leafForRoster(LeafIndex index) throws Exception
    {
        int nonBlankLeaves = 0;
        for (int i = 0; i < tree.size.leafCount(); i++)
        {
            LeafNode leaf = tree.getLeafNode(new LeafIndex(i));
            if (leaf == null)
            {
                continue;
            }
            if (nonBlankLeaves == index.value())
            {
                return new LeafIndex(i);
            }
            nonBlankLeaves++;
        }
        throw new Exception("Invalid roster index");
    }

    public Proposal updateProposal(AsymmetricCipherKeyPair leafSk, LeafNodeOptions leafOptions) throws Exception
    {
        LeafNode leaf = tree.getLeafNode(index);
        LeafNode newLeaf = leaf.forUpdate(suite, groupID, index, suite.getHPKE().serializePublicKey(leafSk.getPublic()), leafOptions, identitySk);

        Proposal update = Proposal.update(newLeaf);
        cachedUpdate = new CachedUpdate(suite.getHPKE().serializePrivateKey(leafSk.getPrivate()), update.update);
        return update;
    }


    private Proposal addProposal(KeyPackage keyPackage) throws Exception
    {
        //TODO: Check that  validity of the signed key package
        if(!keyPackage.verify())
        {
            throw new Exception("Invalid signature on key package");
        }

        //TODO: Check if the Key Package supports the group (capabilities)

        //TODO: Check if the Key Package supports the group extensions

        return Proposal.add(keyPackage);
    }

    private MLSMessage protect(AuthenticatedContent contentAuth, int paddingSize) throws Exception
    {
        MLSMessage message = new MLSMessage(contentAuth.wireFormat); //TODO: change pretect to return MLSMessage instead
        switch (contentAuth.wireFormat)
        {
            case mls_public_message:
                message.publicMessage = PublicMessage.protect(contentAuth, suite, keySchedule.membershipKey.value(), MLSOutputStream.encode(getGroupContext()));
                return message;
            case mls_private_message:
                message.privateMessage = PrivateMessage.protect(contentAuth, suite, keys, keySchedule.senderDataSecret.value(), paddingSize);
                return message;
            default:
                throw new Exception("Malformed AuthenticatedContent");
        }
    }

    //TODO: check if innerContent should be mlsMessage or commit
    private AuthenticatedContent sign(Sender sender, Commit innerContent, byte[] authenticatedData, boolean encrypt) throws Exception
    {
        FramedContent content = FramedContent.rawContent(groupID, epoch, sender, authenticatedData, ContentType.COMMIT, MLSOutputStream.encode(innerContent));
        WireFormat wireFormat = encrypt ? WireFormat.mls_private_message : WireFormat.mls_public_message;
        AuthenticatedContent authContent = AuthenticatedContent.sign(wireFormat, content, suite, identitySk, MLSOutputStream.encode(getGroupContext()));
        return authContent;
    }

    private AuthenticatedContent sign(Sender sender, Proposal innerContent, byte[] authenticatedData, boolean encrypt) throws Exception
    {
        FramedContent content = FramedContent.rawContent(groupID, epoch, sender, authenticatedData, ContentType.PROPOSAL, MLSOutputStream.encode(innerContent));
        WireFormat wireFormat = encrypt ? WireFormat.mls_private_message : WireFormat.mls_public_message;
        AuthenticatedContent authContent = AuthenticatedContent.sign(wireFormat, content, suite, identitySk, MLSOutputStream.encode(getGroupContext()));
        return authContent;
    }
//    private AuthenticatedContent sign(Sender sender, Proposal.Add innerContent, byte[] authenticatedData, boolean encrypt) throws Exception
//    {
//
//        FramedContent content = FramedContent.rawContent(groupID, epoch, sender, authenticatedData, ContentType.PROPOSAL, MLSOutputStream.encode(innerContent));
//        WireFormat wireFormat = encrypt ? WireFormat.mls_private_message : WireFormat.mls_public_message;
//        AuthenticatedContent authContent = AuthenticatedContent.sign(wireFormat, content, suite, identitySk, MLSOutputStream.encode(getGroupContext()));
//        return authContent;
//    }
//    private AuthenticatedContent sign(Sender sender, Proposal.Update innerContent, byte[] authenticatedData, boolean encrypt) throws Exception
//    {
//        FramedContent content = FramedContent.rawContent(groupID, epoch, sender, authenticatedData, ContentType.PROPOSAL, MLSOutputStream.encode(innerContent));
//        WireFormat wireFormat = encrypt ? WireFormat.mls_private_message : WireFormat.mls_public_message;
//        AuthenticatedContent authContent = AuthenticatedContent.sign(wireFormat, content, suite, identitySk, MLSOutputStream.encode(getGroupContext()));
//        return authContent;
//    }
//    private AuthenticatedContent sign(Sender sender, Proposal.Remove innerContent, byte[] authenticatedData, boolean encrypt) throws Exception
//    {
//        FramedContent content = FramedContent.rawContent(groupID, epoch, sender, authenticatedData, ContentType.PROPOSAL, MLSOutputStream.encode(innerContent));
//        WireFormat wireFormat = encrypt ? WireFormat.mls_private_message : WireFormat.mls_public_message;
//        AuthenticatedContent authContent = AuthenticatedContent.sign(wireFormat, content, suite, identitySk, MLSOutputStream.encode(getGroupContext()));
//        return authContent;
//    }
//    private AuthenticatedContent sign(Sender sender, PreSharedKeyID innerContent, byte[] authenticatedData, boolean encrypt) throws Exception
//    {
//        FramedContent content = FramedContent.rawContent(groupID, epoch, sender, authenticatedData, ContentType.PROPOSAL, MLSOutputStream.encode(innerContent));
//        WireFormat wireFormat = encrypt ? WireFormat.mls_private_message : WireFormat.mls_public_message;
//        AuthenticatedContent authContent = AuthenticatedContent.sign(wireFormat, content, suite, identitySk, MLSOutputStream.encode(getGroupContext()));
//        return authContent;
//    }

    private AuthenticatedContent sign(Sender sender, byte[] innerContent, byte[] authenticatedData, boolean encrypt) throws Exception
    {
        FramedContent content = FramedContent.rawContent(groupID, epoch, sender, authenticatedData, ContentType.APPLICATION, innerContent);
        WireFormat wireFormat = encrypt ? WireFormat.mls_private_message : WireFormat.mls_public_message;
        AuthenticatedContent authContent = AuthenticatedContent.sign(wireFormat, content, suite, identitySk, MLSOutputStream.encode(getGroupContext()));
        return authContent;
    }

    private Proposal preSharedKeyProposal(Secret externalPskID)
            throws Exception
    {
        if (!externalPSKs.containsKey(externalPskID))
        {
            throw new Exception("Unknown PSK");
        }
        SecureRandom random = new SecureRandom();
        byte[] nonce = new byte[suite.getKDF().getHashLength()];
        random.nextBytes(nonce);

        return Proposal.preSharedKey(PreSharedKeyID.external(externalPskID.value(), nonce));
    }

    private Proposal removeProposal(LeafIndex removed) throws Exception
    {
        if (!tree.hasLeaf(removed))
        {
            throw new Exception("Removed on blank leaf");
        }

        return Proposal.remove(removed);
    }

    private void updateEpochSecrets(byte[] commitSecret, List<KeyScheduleEpoch.PSKWithSecret> psks, byte[] forceInitSecret) throws Exception
    {
//        System.out.println("commit: " + Hex.toHexString(commitSecret));
        byte[] ctx = MLSOutputStream.encode(new GroupContext(
                suite.getSuiteId(),
                groupID,
                epoch,
                tree.getRootHash(),
                transcriptHash.confirmed,
                extensions
        ));
//        System.out.println("ctx: " + Hex.toHexString(ctx));
        keySchedule = keySchedule.next(tree.size, forceInitSecret, new Secret(commitSecret), psks, ctx);
        keys = keySchedule.getEncryptionKeys(tree.size);
    }

    private JoinersWithPSKS apply(List<CachedProposal> proposals) throws Exception
    {
        applyUpdate(proposals);
//        tree.dump();

        applyRemove(proposals);
//        tree.dump();

        List<LeafIndex> joinerLocs = applyAdd(proposals);
        applyGCE(proposals);
//        tree.dump();

        List<KeyScheduleEpoch.PSKWithSecret> psks = applyPSK(proposals);
//        tree.dump();

//        treePriv.dump();
        tree.truncate();
        treePriv.truncate(tree.size);
        tree.setHashAll();
//        tree.dump();
//        treePriv.dump();

        if (cachedUpdate != null)
        {
            cachedUpdate.reset();
        }
        return new JoinersWithPSKS(joinerLocs, psks);
    }

    private void applyUpdate(List<CachedProposal> proposals) throws Exception
    {
//        List<LeafIndex> locations = new ArrayList<>();
        for (CachedProposal cached: proposals)
        {
            if (cached.proposal.getProposalType() != ProposalType.UPDATE)
            {
                continue;
            }
            if (cached.sender == null)
            {
                throw new Exception("Update without target leaf");
            }
            LeafIndex target = cached.sender;
            if (!target.equals(index))
            {
                tree.updateLeaf(target, cached.proposal.getLeafNode());
                continue;
            }

            if (cachedUpdate == null)
            {
                throw new Exception("Self-update with no cached secret");
            }

            if (!cached.proposal.getLeafNode().equals(cachedUpdate.update.getLeafNode()))
            {
                throw new Exception("Self-update does not match cached data");
            }

            tree.updateLeaf(target, cached.proposal.getLeafNode());
            treePriv.setLeafKey(cachedUpdate.updateSk);
//            locations.add(cached.sender);
        }

        if (cachedUpdate != null)
        {
            cachedUpdate.reset();
        }
//        return locations;
    }

    private boolean extensionsSupported(List<Extension> exts)
    {
        for (int i = 0; i < tree.size.leafCount(); i++)
        {
            LeafIndex leafIndex = new LeafIndex(i);
            LeafNode leaf = tree.getLeafNode(leafIndex);
            if (leaf == null)
            {
                continue;
            }

            if (!leaf.verifyExtensionSupport(exts))
            {
                return false;
            }
        }
        return true;
    }

    private void applyGCE(List<CachedProposal> proposals) throws Exception
    {
//        List<LeafIndex> locations = new ArrayList<>();
        for (CachedProposal cached: proposals)
        {
            if (cached.proposal.getProposalType() != ProposalType.GROUP_CONTEXT_EXTENSIONS)
            {
                continue;
            }

            //TODO: check nex extension is compatible with all members

            if (!extensionsSupported(cached.proposal.groupContextExtensions.extensions))
            {
                throw new Exception("Unsupported extensions in GroupContextExtensions");
            }
            extensions = new ArrayList<>(cached.proposal.groupContextExtensions.extensions);
//            locations.add(tree.addLeaf(cached.proposal.getLeafNode()));
        }
//        return locations;
    }
    private List<KeyScheduleEpoch.PSKWithSecret> applyPSK(List<CachedProposal> proposals) throws Exception
    {
        List<PreSharedKeyID> pskIDs = new ArrayList<>();
        for (CachedProposal cached: proposals)
        {
            if (cached.proposal.getProposalType() != ProposalType.PSK)
            {
                continue;
            }

            pskIDs.add(cached.proposal.preSharedKey.psk);
        }
        return resolve(pskIDs);
    }
    private List<LeafIndex> applyAdd(List<CachedProposal> proposals)
    {
        List<LeafIndex> locations = new ArrayList<>();
        for (CachedProposal cached: proposals)
        {
            if (cached.proposal.getProposalType() != ProposalType.ADD)
            {
                continue;
            }
            locations.add(tree.addLeaf(cached.proposal.getLeafNode()));
        }
        return locations;
    }
    private void applyRemove(List<CachedProposal> proposals) throws Exception
    {
//        List<LeafIndex> locations = new ArrayList<>();
        for (CachedProposal cached: proposals)
        {
            if (cached.proposal.getProposalType() != ProposalType.REMOVE)
            {
                continue;
            }

            if(!tree.hasLeaf(cached.proposal.remove.removed))
            {
                throw new Exception("Attempt to remove non-member");
            }

            tree.blankPath(cached.proposal.remove.removed);

//            locations.add(cached.proposal.remove.removed);
        }
//        return locations;
    }

    private Group successor() throws IOException
    {
        Group next = new Group();
        //TODO: check which needs to be deep copied
        next.externalPSKs = new HashMap<>(externalPSKs);
        next.resumptionPSKs = new HashMap<>();
        next.resumptionPSKs.putAll(resumptionPSKs);
        next.epoch = epoch;
        next.groupID = groupID.clone();
        next.transcriptHash = transcriptHash.copy();
        next.extensions = new ArrayList<>();
        next.extensions.addAll(extensions);
        next.keySchedule = keySchedule; // check
        next.tree = TreeKEMPublicKey.clone(tree);
        next.treePriv = treePriv.copy();
        next.keys = keys; // check
        next.suite = suite;
        next.index = index;
        next.identitySk = identitySk.clone();

//        next.pendingProposals = new ArrayList<>(pendingProposals);
        next.pendingProposals = new ArrayList<>();
        next.cachedUpdate = cachedUpdate;

//        next.resumptionPSKs = new HashMap<>();
        next.resumptionPSKs.put(new EpochRef(groupID, epoch), keySchedule.resumptionPSK.value().clone());

        return next;
    }


    private boolean pathRequired(List<CachedProposal> proposals)
    {
        if (proposals.isEmpty())
        {
            return true;
        }
        for (CachedProposal cached: proposals)
        {
            switch (cached.proposal.getProposalType())
            {
                case UPDATE:
                case REMOVE:
                case EXTERNAL_INIT:
                case GROUP_CONTEXT_EXTENSIONS:
                    return true;
                default:
                    break;
            }
        }
        return false;
    }

    public byte[] getEpochAuthenticator()
    {
        return keySchedule.epochAuthenticator.value();
    }

    private void cacheProposal(AuthenticatedContent auth) throws Exception
    {
        byte[] ref = suite.refHash(MLSOutputStream.encode(auth), "MLS 1.0 Proposal Reference");

        // check if ref is already in the queue
        for (CachedProposal cached: pendingProposals)
        {
            if (Arrays.equals(cached.proposalRef, ref))
            {
                return;
            }
        }
//        Sender sender = null;
        LeafIndex senderLocation = null;
        if (auth.content.sender.senderType == SenderType.MEMBER)
        {
            senderLocation = auth.content.sender.sender;
        }

        Proposal proposal = auth.content.proposal;
        if (!validateProposal(senderLocation, proposal))
        {
            throw new Exception("Invalid proposal");
        }
        //TODO: check if ref should be recalculated
        pendingProposals.add(new CachedProposal(ref, proposal, senderLocation));
    }


    private boolean validateProposal(LeafIndex sender, Proposal proposal) throws IOException
    {
        switch (proposal.getProposalType())
        {
            case UPDATE:
                return validateUpdate(sender, proposal.update);
            case ADD:
                return validateKeyPackage(proposal.add.keyPackage);
            case REMOVE:
                return validateRemove(proposal.remove);
            case PSK:
                return validatePSK(proposal.preSharedKey);
            case REINIT:
                return validateReinit(proposal.reInit);
            case EXTERNAL_INIT:
                return validateExternalInit(proposal.externalInit);
            case GROUP_CONTEXT_EXTENSIONS:
                return validateGCE(proposal.groupContextExtensions);
            default:
                return false;
        }
    }

    private boolean validateGCE(Proposal.GroupContextExtensions gce)
    {
        // Verify that each extension is supported by all members
        for (int i = 0; i < tree.size.leafCount(); i++)
        {
            LeafIndex index = new LeafIndex(i);
            LeafNode leaf = tree.getLeafNode(index);
            if (leaf == null)
            {
                continue;
            }

            if (!leaf.verifyExtensionSupport(gce.extensions))
            {
                return false;
            }
        }
        return true;
    }
    private boolean validateExternalInit(Proposal.ExternalInit ext)
    {
        return ext.kemOutput.length == suite.getHPKE().getEncSize();
    }
    private boolean validateReinit(Proposal.ReInit reInit)
    {
        // Check that the version and CipherSuite are ones we support
        boolean supportedVersion = (reInit.version == ProtocolVersion.mls10);
        boolean supportedSuite = true; //TODO: make a list of supported cipher suites

        return supportedSuite && supportedVersion;
    }

    private boolean validateReinitProposals(List<CachedProposal> proposals)
    {
        boolean hasReinit = false;
        boolean hasDisallowed = false;
        for (CachedProposal cached : proposals)
        {
            hasReinit = hasReinit || cached.proposal.getProposalType() == ProposalType.REINIT;
            hasDisallowed = hasDisallowed || cached.proposal.getProposalType() != ProposalType.REINIT;
        }
        return  hasReinit && !hasDisallowed;
    }
    private boolean validatePSK(Proposal.PreSharedKey psk)
    {
        switch (psk.psk.pskType)
        {
            case EXTERNAL:
                // External PSKs are allowed if we have the corresponding secret
                return externalPSKs.containsKey(psk.psk.external.externalPSKID);
            case RESUMPTION:
                // Resumption PSKs are allowed only with usage 'application', and only if we
                // have the corresponding secret.
                PreSharedKeyID.Resumption res = psk.psk.resumption;
                if (res.resumptionPSKUsage != ResumptionPSKUsage.APPLICATION)
                {
                    return false;
                }
                return (res.pskEpoch == epoch) || resumptionPSKs.containsKey(new EpochRef(res.pskGroupID, res.pskEpoch));
            default:
                return false;
        }
    }

    private boolean validateRemove(Proposal.Remove remove)
    {
        // We mark self-removes invalid here even though a resync Commit will
        // sometimes cause them.  This is OK because this method is only called from
        // the normal proposal list validation method, not the external commit one.
        //TODO: check if tree size leafCount or tree size Width
        boolean in_tree = (remove.removed.value() < tree.size.leafCount()) && tree.hasLeaf(remove.removed);
        boolean not_me = remove.removed.value() != index.value();
        return in_tree && not_me;
    }

    private boolean validateKeyPackage(KeyPackage keyPackage) throws IOException
    {
        // Verify that the ciphersuite and protocol version of the KeyPackage match
        // those in the GroupContext.
        boolean correct_ciphersuite = (keyPackage.cipher_suite == suite.getSuiteId());

        // Verify that the signature on the KeyPackage is valid using the public key
        // in leaf_node.credential.
        //TODO: check why these are false: valid_signature and leaf_node_valid
        boolean valid_signature = keyPackage.verify();

        // Verify that the leaf_node of the KeyPackage is valid for a KeyPackage
        // according to Section 7.3.
        boolean leaf_node_valid = validateLeafNode(keyPackage.leaf_node, LeafNodeSource.KEY_PACKAGE, null);

        // Verify that the value of leaf_node.encryption_key is different from the
        // value of the init_key field.
        boolean distinct_keys = !Arrays.equals(keyPackage.init_key, keyPackage.leaf_node.encryption_key);

//        if (!(correct_ciphersuite && valid_signature && leaf_node_valid && distinct_keys))
//        {
//            System.out.println("correct_ciphersuite: " + correct_ciphersuite);
//            System.out.println("valid_signature: " + valid_signature);
//            System.out.println("leaf_node_valid: " + leaf_node_valid);
//            System.out.println("distinct_keys: " + distinct_keys);
//        }

        return (correct_ciphersuite && valid_signature && leaf_node_valid && distinct_keys);
    }
    private boolean validateUpdate(LeafIndex sender, Proposal.Update update) throws IOException
    {
        LeafNode leaf = tree.getLeafNode(sender);
        if (leaf == null)
        {
            return false;
        }

        return validateLeafNode(update.getLeafNode(), LeafNodeSource.UPDATE, sender);
    }

    private boolean validateLeafNode(LeafNode leafNode, LeafNodeSource requiredSource, LeafIndex index) throws IOException
    {
        //TODO: Check all verifications are covered in (https://www.ietf.org/archive/id/draft-ietf-mls-protocol-20.html#section-7.3)

        //TODO: Validate the credential in the LeafNode is valid:
        // (https://www.ietf.org/archive/id/draft-ietf-mls-protocol-20.html#name-credential-validation)

        // Verify leaf node source
        boolean isCorrectSource = (leafNode.getSource() == requiredSource);

        // Verify LeafNode signature with signature key
        byte[] tbs;
        switch (requiredSource)
        {
            case UPDATE:
            case COMMIT:
                tbs = leafNode.toBeSigned(groupID, index.value());
                break;
            default:
                tbs = leafNode.toBeSigned(null, -1);
                break;
        }
        boolean isSignatureValid = leafNode.verify(suite, tbs);


        //TODO:
        // Verify that the LeafNode is compatible with the group's parameters. If the
        // GroupContext has a required_capabilities extension, then the required
        // extensions, proposals, and credential types MUST be listed in the
        // LeafNode's capabilities field.
        boolean supportsGroupExtensions = true;
//                = leafNode.verifyExtensionSupport(extensions);

        // Verify the lifetime
        boolean isLifetimeValid = leafNode.verifyLifetime(); // TODO: check if needed (RECOMMENDED)


        //TODO:
        // Verify that the credential type is supported by all members of the group,
        // as specified by the capabilities field of each member's LeafNode, and that
        // the capabilities field of this LeafNode indicates support for all the
        // credential types currently in use by other members.
        boolean mutualCredentialSupport = true;

        // Verify that the following fields are unique among the members of the group:
        // signature_key
        // encryption_key
        boolean isUniqueSigKey = true;
        boolean isUniqueEncKey = true;
        byte[] sigKey = leafNode.signature_key;
        byte[] encKey = leafNode.encryption_key;

        for (int i = 0; i < tree.size.leafCount(); i++)
        {
            LeafNode leaf = tree.getLeafNode(new LeafIndex(i));
            if (leaf == null)
            {
                continue;
            }

            isUniqueSigKey &= (index != null && ((i == index.value())) || (!Arrays.equals(sigKey, leaf.signature_key)));
            isUniqueEncKey &= !Arrays.equals(encKey, leaf.encryption_key);
            //TODO:
//            mutualCredentialSupport &= leaf.capabilities.credentialSupported(leafNode.credential)
//                    && leafNode.capabilities.credentialSupported(leaf.credential)
        }



        //TODO:
        // Verify that the extensions in the LeafNode are supported
        // by checking that the ID for each extension in the extensions field is listed in the
        // capabilities.extensions field of the LeafNode.
        boolean supportsAllExtensions = true;
        for (Extension ext : leafNode.extensions)
        {
            supportsAllExtensions &= leafNode.capabilities.extensions.contains(ext.extensionType.getValue());
        }

        if (!(isCorrectSource && isSignatureValid && isLifetimeValid && supportsAllExtensions
                && isUniqueSigKey && isUniqueEncKey && mutualCredentialSupport && supportsGroupExtensions))
        {
            System.out.println("validLeaf-uniqueSigKey: " + isUniqueSigKey);
            System.out.println("validLeaf-uniqueEncKey: " + isUniqueEncKey);
            System.out.println("validLeaf-mutCredSup: " + mutualCredentialSupport);
            System.out.println("validLeaf-supAllExt: " + supportsAllExtensions);
            System.out.println("validLeaf-correctSource: " + isCorrectSource);
            System.out.println("validLeaf-signatureValid: " + isSignatureValid);
            System.out.println("validLeaf-lifetimeValid: " + isLifetimeValid);
        }

        return (isCorrectSource && isSignatureValid && isLifetimeValid && supportsAllExtensions
                && isUniqueSigKey && isUniqueEncKey && mutualCredentialSupport && supportsGroupExtensions);
    }

    private boolean validateCachedProposals(List<CachedProposal> proposals, LeafIndex commitSender, CommitParameters params) throws IOException
    {
        switch (params.paramID)
        {
            case NORMAL_COMMIT_PARAMS:
                return validateNormalCachedProposals(proposals, commitSender);
            case EXTERNAL_COMMIT_PARAMS:
                return validateExternalCachedProposals(proposals);
            case RESTART_COMMIT_PARAMS:
                return validateRestartCachedProposals(proposals, params.allowedUsage);
            case REINIT_COMMIT_PARAMS:
                return validateReInitCachedProposals(proposals);
        }
        return false;
    }
    private boolean validateReInitCachedProposals(List<CachedProposal> proposals)
    {
        // Check that the list contains a ReInit proposal
        boolean has_reinit = false;

        // Check whether the list contains any disallowed proposals
        boolean has_disallowed = false;

        for (CachedProposal cached : proposals)
        {
            has_reinit = has_reinit || (cached.proposal.getProposalType() == ProposalType.REINIT);
            has_disallowed = has_disallowed || (cached.proposal.getProposalType() != ProposalType.REINIT);
        }

        return has_reinit && !has_disallowed;
    }
    private boolean validateRestartCachedProposals(List<CachedProposal> proposals, ResumptionPSKUsage allowedUsage)
    {
        // Check that the list has exactly one resumption PSK proposal with the
        // allowed usage and any other PSKs are external
        boolean foundAllowed = false;
        boolean acceptable_psks = true;
        for (CachedProposal cached : proposals)
        {
            if (cached.proposal.getProposalType() != ProposalType.PSK)
            {
                continue;
            }

            PreSharedKeyID psk = cached.proposal.preSharedKey.psk;
            if (psk.pskType == PSKType.EXTERNAL)
            {
                continue;
            }

            boolean allowed = psk.resumption.resumptionPSKUsage == allowedUsage;
            if (foundAllowed && allowed)
            {
                acceptable_psks = false;
                continue;
            }
            foundAllowed = foundAllowed || allowed;
        }
        return acceptable_psks && foundAllowed;
    }
    private boolean validateNormalCachedProposals(List<CachedProposal> proposals, LeafIndex commitSender) throws IOException
    {
        //TODO: use Java 8 streams?
        // It contains an individual proposal that is invalid as specified in Section
        // 12.1.
        boolean has_invalid_proposal = false;

        // It contains an Update proposal generated by the committer.
        boolean has_self_update = false;

        // It contains a Remove proposal that removes the committer.
        boolean has_self_remove = false;

        for (CachedProposal cached : proposals)
        {
            has_invalid_proposal = has_invalid_proposal || !validateProposal(cached.sender, cached.proposal);
            has_self_update = has_self_update || ((cached.proposal.getProposalType() == ProposalType.UPDATE) && cached.sender.equals(commitSender));
            has_self_remove = has_self_remove || ((cached.proposal.getProposalType() == ProposalType.REMOVE) && (cached.proposal.remove.removed.equals(commitSender)));
        }

        // It contains multiple Update and/or Remove proposals that apply to the same
        // leaf. If the committer has received multiple such proposals they SHOULD
        // prefer any Remove received, or the most recent Update if there are no
        // Removes.
        Set<LeafIndex> updatedOrRemoved = new HashSet<>();
        boolean has_dup_update_remove = false;
        for (CachedProposal cached : proposals)
        {
            LeafIndex leafIndex;
            switch (cached.proposal.getProposalType())
            {
                case UPDATE:
                    leafIndex = cached.sender;
                    break;
                case REMOVE:
                    leafIndex = cached.proposal.remove.removed;
                    break;
                default:
                    continue;
            }
            if (updatedOrRemoved.contains(leafIndex))
            {
                has_dup_update_remove = true;
                continue;
            }

            updatedOrRemoved.add(leafIndex);
        }

        // It contains multiple Add proposals that contain KeyPackages that represent
        // the same client according to the application (for example, identical
        // signature keys).
        List<byte[]> signatureKeys = new ArrayList<>();
        boolean has_dup_signature_key = false;
        for (CachedProposal cached : proposals)
        {
            if (cached.proposal.getProposalType() != ProposalType.ADD)
            {
                continue;
            }
            KeyPackage keyPackage = cached.proposal.add.keyPackage;
            byte[] signatureKey = keyPackage.leaf_node.signature_key;
            boolean areEqual = false;
            for (byte[] sig : signatureKeys)
            {
                if(Arrays.equals(sig, signatureKey))
                {
                    areEqual = true;
                    break;
                }
            }
            if (areEqual)
            {
                has_dup_signature_key = true;
                continue;
            }

            signatureKeys.add(signatureKey);
        }

        //TODO
        // It contains an Add proposal with a KeyPackage that represents a client
        // already in the group according to the application, unless there is a Remove
        // proposal in the list removing the matching client from the group.

        // It contains multiple PreSharedKey proposals that reference the same
        // PreSharedKeyID.
        //TODO: how to compare PSK id
        List<PreSharedKeyID> pskids = new ArrayList<>();
        boolean has_dup_psk_id = false;
        for (CachedProposal cached : proposals)
        {
            if (cached.proposal.getProposalType() != ProposalType.PSK)
            {
                continue;
            }
            PreSharedKeyID pskid = cached.proposal.preSharedKey.psk;
            if (pskids.contains(pskid))
            {
                has_dup_psk_id = true;
                continue;
            }

            pskids.add(pskid);
        }

        // It contains multiple GroupContextExtensions proposals.
        int gceCount = 0;
        for (CachedProposal cached : proposals)
        {
            if (cached.proposal.getProposalType() == ProposalType.GROUP_CONTEXT_EXTENSIONS)
            {
               gceCount++;
            }
        }
        boolean has_multiple_gce = (gceCount > 1);

        // It contains a ReInit proposal together with any other proposal. If the
        // committer has received other proposals during the epoch, they SHOULD prefer
        // them over the ReInit proposal, allowing the ReInit to be resent and applied
        // in a subsequent epoch.
        boolean has_reinit = false;

        // It contains an ExternalInit proposal.
        boolean has_external_init = false;

        for (CachedProposal cached : proposals)
        {
            has_reinit = has_reinit || (cached.proposal.getProposalType() == ProposalType.REINIT);
            has_external_init = has_external_init || (cached.proposal.getProposalType() == ProposalType.EXTERNAL_INIT);
        }

        //TODO: check
        // It contains a proposal with a non-default proposal type that is not
        // supported by some members of the group that will process the Commit (i.e.,
        // members being added or removed by the Commit do not need to support the
        // proposal type).
        // XXX(RLB): N/A, no non-default proposal types

        // After processing the commit the ratchet tree is invalid, in particular, if
        // it contains any leaf node that is invalid according to Section 7.3.
        //
        //TODO: check
        // NB(RLB): Leaf nodes are already checked in the individual proposal check at
        // the top.  So the focus here is key uniqueness. We check this by checking
        // uniqueness of encryption keys across the Adds and Updates in this list of
        // proposals.  The keys have already been checked to be distinct from any keys
        // already in the tree.
        List<byte[]> encKeys = new ArrayList<>();
        boolean has_dup_enc_key = false;
        for (CachedProposal cached : proposals)
        {
            byte[] encKey;
            switch (cached.proposal.getProposalType())
            {
                case ADD:
                    encKey = cached.proposal.add.keyPackage.leaf_node.encryption_key.clone();
                    break;
                case UPDATE:
                    encKey = cached.proposal.update.getLeafNode().encryption_key.clone();
                    break;
                default:
                    continue;
            }

            boolean areEqual = false;
            for (byte[] key : encKeys)
            {
                if(Arrays.equals(key, encKey))
                {
                    areEqual = true;
                    break;
                }
            }
            if (areEqual)
            {
                has_dup_enc_key = true;
                continue;
            }

            encKeys.add(encKey);
        }

        return !(has_invalid_proposal || has_self_update || has_self_remove ||
                has_dup_update_remove || has_dup_signature_key || has_dup_psk_id ||
                has_multiple_gce || has_reinit || has_external_init ||
                has_dup_enc_key);
    }
    private boolean validateExternalCachedProposals(List<CachedProposal> proposals)
    {
        //TODO: do for other parameters
        // this is for external commit parameters
        int extInitCount = 0;
        int removeCount = 0;
        boolean noDisallowed = true;
        for (CachedProposal cached : proposals)
        {
            switch (cached.proposal.getProposalType())
            {

                case EXTERNAL_INIT:
                    extInitCount++;
                    break;
                case REMOVE:
                    removeCount++;
                    break;
                case PSK:
                    noDisallowed = noDisallowed && validatePSK(cached.proposal.preSharedKey);
                    break;
                default:
                    noDisallowed = false;
                    break;
            }
        }
        boolean hasOneExtInit = (extInitCount == 1);
        boolean noDupRemove = (removeCount <= 1);

        return (hasOneExtInit && noDupRemove && noDisallowed);
    }

    private List<CachedProposal> mustResolve(List<ProposalOrRef> proposals, LeafIndex sender)
    {
        List<CachedProposal> out = new ArrayList<>();
        for (ProposalOrRef id : proposals)
        {
            switch (id.type)
            {
                case PROPOSAL:
                    out.add(new CachedProposal(new byte[0], id.proposal, sender));
                    break;
                case REFERENCE:
                    for (CachedProposal cached : pendingProposals)
                    {
//                        System.out.println("cachedRef: " + Hex.toHexString(cached.proposalRef));
//                        System.out.println("idRef: " + Hex.toHexString(id.reference));
                        if (Arrays.equals(cached.proposalRef, id.reference))
                        {
                            out.add(cached);
                            break;
                        }
                    }
                    break;
            }
        }
        return out;
    }

    private GroupContext  getGroupContext() throws Exception
    {
        return new GroupContext(suite.getSuiteId(), groupID, epoch, tree.getRootHash(), transcriptHash.confirmed, extensions);
    }

    private TreeKEMPublicKey importTree(byte[] treeHash, TreeKEMPublicKey external, List<Extension> extensions) throws Exception
    {
        // Check if extensions contain a ratchet tree
        TreeKEMPublicKey outTree = null;
        for (Extension ext : extensions)
        {
            outTree = ext.getRatchetTree();
            if (outTree != null)
            {
                break;
            }
        }
        if (external != null)
        {
            //TODO: check if it should be a deep copy
            outTree = external;
        }
        else if (outTree == null)
        {
            throw new Exception("No tree available");
        }

        outTree.setSuite(suite);
        outTree.setHashAll();
        if (!Arrays.equals(outTree.getRootHash(), treeHash))
        {
            throw new Exception("Tree does not match GroupInfo");
        }

        if (!outTree.verifyParentHash())
        {
            throw new Exception("Invalid tree");
        }

        return outTree;
    }

    private List<KeyScheduleEpoch.PSKWithSecret> resolve(List<PreSharedKeyID> psks) throws Exception
    {
        List<KeyScheduleEpoch.PSKWithSecret> out = new ArrayList<>();
        for (PreSharedKeyID psk : psks)
        {
            switch (psk.pskType)
            {
                case EXTERNAL:
                    if (!externalPSKs.containsKey(psk.external.externalPSKID))
                    {
                        throw new Exception("Unknown external PSK");
                    }
                    out.add(new KeyScheduleEpoch.PSKWithSecret(psk, new Secret(externalPSKs.get(psk.external.externalPSKID))));
                    break;
                case RESUMPTION:
                    if (psk.resumption.pskEpoch == epoch)
                    {
                        out.add(new KeyScheduleEpoch.PSKWithSecret(psk, keySchedule.resumptionPSK));
                    }
                    else
                    {
                        EpochRef key = new EpochRef(psk.resumption.pskGroupID, psk.resumption.pskEpoch);
                        if (!resumptionPSKs.containsKey(key))
                        {
                            throw new Exception("Unknown resumption PSK");
                        }
                        out.add(new KeyScheduleEpoch.PSKWithSecret(psk, new Secret(resumptionPSKs.get(key).clone())));
                    }
                    break;
            }
        }
        return out;
    }
}
