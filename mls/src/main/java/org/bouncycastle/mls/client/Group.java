package org.bouncycastle.mls.client;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.mls.GroupKeySet;
import org.bouncycastle.mls.KeyScheduleEpoch;
import org.bouncycastle.mls.TranscriptHash;
import org.bouncycastle.mls.TreeKEM.LeafIndex;
import org.bouncycastle.mls.TreeKEM.LeafNode;
import org.bouncycastle.mls.TreeKEM.LeafNodeSource;
import org.bouncycastle.mls.TreeKEM.NodeIndex;
import org.bouncycastle.mls.TreeKEM.TreeKEMPrivateKey;
import org.bouncycastle.mls.TreeKEM.TreeKEMPublicKey;
import org.bouncycastle.mls.codec.AuthenticatedContent;
import org.bouncycastle.mls.codec.Commit;
import org.bouncycastle.mls.codec.Extension;
import org.bouncycastle.mls.codec.FramedContent;
import org.bouncycastle.mls.codec.GroupContext;
import org.bouncycastle.mls.codec.GroupInfo;
import org.bouncycastle.mls.codec.GroupSecrets;
import org.bouncycastle.mls.codec.KeyPackage;
import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSMessage;
import org.bouncycastle.mls.codec.MLSOutputStream;
import org.bouncycastle.mls.codec.PreSharedKeyID;
import org.bouncycastle.mls.codec.Proposal;
import org.bouncycastle.mls.codec.ProposalOrRef;
import org.bouncycastle.mls.codec.ProposalType;
import org.bouncycastle.mls.codec.ProtocolVersion;
import org.bouncycastle.mls.codec.SenderType;
import org.bouncycastle.mls.codec.UpdatePath;
import org.bouncycastle.mls.codec.Welcome;
import org.bouncycastle.mls.crypto.CipherSuite;
import org.bouncycastle.mls.crypto.Secret;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Group
{
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
            this.id = id;
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
    private Map<Secret, byte[]> externalPSKs;
    private Map<EpochRef, byte[]> resumptionPSKs;
    private long epoch;
    private byte[] groupID;
    private TranscriptHash transcriptHash;
    private ArrayList<Extension> extensions;
    private KeyScheduleEpoch keySchedule;
    private TreeKEMPublicKey tree;
    private TreeKEMPrivateKey treePriv;
    private GroupKeySet keys;
    private CipherSuite suite;
    private LeafIndex index;
    private byte[] identitySk;
//    private ArrayList<CachedProposal> proposalQueue;
    private ArrayList<CachedProposal> pendingProposals;
    private CachedUpdate cachedUpdate;

    //TODO: maybe make this an ordered map
    List<Client> members;

    public Group()
    {
    }

    public Group(Client creator)
    {
        members = new ArrayList<>();
        members.add(creator);
    }

    // Creates a group from a welcome message
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
        this.resumptionPSKs = resumptionPsks;

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

        transcriptHash.confirmed = groupInfo.groupContext.confirmedTranscriptHash;
        transcriptHash.updateInterim(groupInfo.confirmationTag);

        extensions = groupInfo.groupContext.extensions; // TODO: Check to clone?

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

        // Validate the GroupContext
        FramedContent content = auth.content;
        if (!Arrays.equals(content.group_id, groupID))
        {
            throw new Exception("GroupID mismatch");
        }
        if (content.epoch != epoch)
        {
            throw new Exception("Epoch mismatch");
        }

        switch (content.getContentType()) {
            // Proposals get queued, do not result in a state transition
            case PROPOSAL:
                cacheProposal(auth);//todo: cache proposal
                return null;

            // Commits are handled in the remainder of this method
            case COMMIT:
                break;

            // Any other content type in this method is an error
            default:
                throw new Exception("Invalid content type");
        }

        // Handling the Commit
        switch (auth.content.sender.senderType)
        {
            case MEMBER:
            case NEW_MEMBER_COMMIT:
                break;
            default:
                throw new Exception("Invalid commit sender type");
        }

        LeafIndex sender = new LeafIndex(auth.content.sender.node_index);
        if (sender.equals(index))
        {
            if (cachedGroup != null)
            {
                // Verify cached group
                if (!Arrays.equals(cachedGroup.groupID, groupID) ||
                    cachedGroup.epoch != (epoch + 1) ||
                    cachedGroup.index != index)
                {
                    throw new Exception("Invalid successor state");
                }

                return cachedGroup;
            }
            throw new Exception("Handle own commits with caching");
        }

        // Apply the commit
        Commit commit = auth.content.commit;
        List<CachedProposal> proposals = mustResolve(commit.proposals, sender);

        //TODO:
        // Validate commit type with expected type and get commit params
        // if there is no expected type
        // validate if it us a valid external or normal commit
        // External commit -> KeyPackage (joiner), byte[] (forceInitSecret)
        // Normal commit -> nothing
        // ReInit commit -> nothing
        // Branch/Restart commit -> ResumptionPSKUsage (allowedUsage)
        boolean externalcommit = false;
        for (CachedProposal cached: proposals)
        {
            if (cached.proposal.getProposalType() == ProposalType.EXTERNAL_INIT)
            {
                externalcommit = true;
            }
        }

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

        byte[] forceInitSecret = new byte[suite.getKDF().getHashLength()];
        LeafIndex senderLocation = new LeafIndex(0);
        if(!externalcommit)
        {
            senderLocation = sender;
        }
        else
        {
            // Add the joiner
            UpdatePath path = commit.updatePath;
            senderLocation = next.tree.addLeaf(path.leaf_node);

            // Extract the forced init secret
            byte[] kemOut = commit.validityExternal();
            if (kemOut == null)
            {
                throw new Exception("Invalid external commit");
            }
            KeyScheduleEpoch.ExternalInitParams extParams = new KeyScheduleEpoch.ExternalInitParams(suite, suite.getHPKE().deserializePublicKey(kemOut));
            forceInitSecret = extParams.getKEMOutput();
        }

        // Decapsulate and apply the UpdatePath, if provided
        byte[] commitSecret = new byte[suite.getKDF().getHashLength()];
        if (commit.updatePath != null)
        {
            if (!validateLeafNode(commit.updatePath.leaf_node, LeafNodeSource.COMMIT, senderLocation))
            {
                throw new Exception("Commit path has invalid leaf node");
            }

            if (!next.tree.verifyParentHash(senderLocation, commit.updatePath))
            {
                throw new Exception("Commit path has invalid parent hash");
            }

            next.tree.merge(senderLocation, commit.updatePath);

            byte[] ctx = MLSOutputStream.encode(new GroupContext(
               next.suite.getSuiteId(),
               next.groupID,
               next.epoch + 1,
               next.tree.getRootHash(),
               next.transcriptHash.confirmed,
               next.extensions
            ));
            next.treePriv.decap(
                    senderLocation,
                    next.tree,
                    ctx,
                    commit.updatePath,
                    joinersWithPSKS.joiners
                );
            commitSecret = next.treePriv.updateSecret.value();
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

    private void updateEpochSecrets(byte[] commitSecret, List<KeyScheduleEpoch.PSKWithSecret> psks, byte[] forceInitSecret) throws Exception
    {
        byte[] ctx = MLSOutputStream.encode(new GroupContext(
                suite.getSuiteId(),
                groupID,
                epoch,
                tree.getRootHash(),
                transcriptHash.confirmed,
                extensions
        ));
        keySchedule = keySchedule.next(tree.size, forceInitSecret, new Secret(commitSecret), psks, ctx);
        keys = keySchedule.getEncryptionKeys(tree.size);
    }

    private JoinersWithPSKS apply(List<CachedProposal> proposals) throws Exception
    {
        applyUpdate(proposals);
        applyRemove(proposals);
        List<LeafIndex> joinerLocs = applyAdd(proposals);
        applyGCE(proposals);
        List<KeyScheduleEpoch.PSKWithSecret> psks = applyPSK(proposals);

        tree.truncate();
        treePriv.truncate(tree.size);
        tree.setHashAll();
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

            if (cached.sender != index)
            {
                tree.updateLeaf(cached.sender, cached.proposal.getLeafNode());
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

            tree.updateLeaf(cached.sender, cached.proposal.getLeafNode());
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
            extensions = cached.proposal.groupContextExtensions.extensions;
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
        next.resumptionPSKs = new HashMap<>(resumptionPSKs);
        next.epoch = epoch;
        next.groupID = groupID.clone();
        next.transcriptHash = transcriptHash;
        next.extensions = new ArrayList<>(extensions);
        next.keySchedule = keySchedule; // check
        next.tree = TreeKEMPublicKey.clone(tree);
        next.treePriv = treePriv.copy();
        next.keys = keys; // check
        next.suite = suite;
        next.index = index;
        next.identitySk = identitySk.clone();
//        next.proposalQueue = new ArrayList<>(proposalQueue); // check
        next.pendingProposals = new ArrayList<>();
        next.cachedUpdate = cachedUpdate;

        next.resumptionPSKs.put(new EpochRef(groupID, epoch), keySchedule.resumptionPSK.value());

        return next;
    }

    private boolean pathRequired(List<CachedProposal> proposals)
    {
        for (CachedProposal cached: proposals)
        {
            switch (cached.proposal.getProposalType())
            {
                case UPDATE:
                case REMOVE:
                case EXTERNAL_INIT:
                case GROUP_CONTEXT_EXTENSIONS:
                    break;
                default:
                    return false;
            }
        }
        return true;
    }

    public byte[] getEpochAuthenticator()
    {
        return keySchedule.epochAuthenticator.value();
    }

    private void cacheProposal(AuthenticatedContent auth) throws IOException
    {
        byte[] ref = suite.refHash(MLSOutputStream.encode(auth), "MLS 1.0 KeyPackage Reference");
        //TODO:
        // check if ref is already in the queue

        LeafIndex senderIndex;
        if (auth.content.sender.senderType == SenderType.MEMBER)
        {
            senderIndex = new LeafIndex(auth.content.sender.node_index);
        }

        //TODO: check if proposal is valid


    }


    private boolean validateSender(LeafIndex sender, Proposal proposal) throws IOException
    {
        LeafNode leaf = tree.getLeafNode(sender);
        if (leaf == null)
        {
            return false;
        }

        return validateLeafNode(proposal.getLeafNode(), LeafNodeSource.UPDATE, sender);
    }

    private boolean validateLeafNode(LeafNode leafNode, LeafNodeSource requiredSource, LeafIndex index) throws IOException
    {
        //TODO: Check all verifications are covered in (https://www.ietf.org/archive/id/draft-ietf-mls-protocol-20.html#section-7.3)

        //TODO: Validate the credential in the LeafNode is valid:
        // (https://www.ietf.org/archive/id/draft-ietf-mls-protocol-20.html#name-credential-validation)

        // Verify leaf node source
        boolean isCorrectSource = (leafNode.getSource() == requiredSource);
        System.out.println("validLeaf-correctSource: " + isCorrectSource);

        // Verify LeafNode signature with signature key
        byte[] tbs;
        switch (requiredSource)
        {
            case UPDATE:
            case COMMIT:
                tbs = leafNode.toBeSigned(groupID, index.value());
                break;
            default:
                tbs = new byte[0];
                break;
        }
        boolean isSignatureValid = leafNode.verify(suite, tbs);
        System.out.println("validLeaf-signatureValid: " + isSignatureValid);


        //TODO:
        // Verify that the LeafNode is compatible with the group's parameters. If the
        // GroupContext has a required_capabilities extension, then the required
        // extensions, proposals, and credential types MUST be listed in the
        // LeafNode's capabilities field.
        boolean supportsGroupExtensions = true;
//                = leafNode.verifyExtensionSupport(extensions);

        // Verify the lifetime
        boolean isLifetimeValid = leafNode.verifyLifetime(); // TODO: check if needed (RECOMMENDED)
        System.out.println("validLeaf-lifetimeValid: " + isLifetimeValid);


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

            isUniqueSigKey &= ((i == index.value()) || (!Arrays.equals(sigKey, leaf.signature_key)));
            isUniqueEncKey &= !Arrays.equals(encKey, leaf.encryption_key);
            //TODO:
//            mutualCredentialSupport &= leaf.capabilities.credentialSupported(leafNode.credential)
//                    && leafNode.capabilities.credentialSupported(leaf.credential)
        }

        System.out.println("validLeaf-uniqueSigKey: " + isUniqueSigKey);
        System.out.println("validLeaf-uniqueEncKey: " + isUniqueEncKey);
        System.out.println("validLeaf-mutCredSup: " + mutualCredentialSupport);


        //TODO:
        // Verify that the extensions in the LeafNode are supported
        // by checking that the ID for each extension in the extensions field is listed in the
        // capabilities.extensions field of the LeafNode.
        boolean supportsAllExtensions = true;
        for (Extension ext : leafNode.extensions)
        {
            supportsAllExtensions &= leafNode.capabilities.extensions.contains(ext.extensionType.getValue());
        }
        System.out.println("validLeaf-supAllExt: " + supportsAllExtensions);


        return (isCorrectSource && isSignatureValid && isLifetimeValid && supportsAllExtensions
                && isUniqueSigKey && isUniqueEncKey && mutualCredentialSupport && supportsGroupExtensions);
    }

    private List<CachedProposal> mustResolve(List<ProposalOrRef> proposals,  LeafIndex senderIndex)
    {
        List<CachedProposal> out = new ArrayList<>();
        for (ProposalOrRef id : proposals)
        {
            switch (id.type)
            {
                case PROPOSAL:
                    out.add(new CachedProposal(new byte[0], id.proposal, senderIndex));
                    break;
                case REFERENCE:
                    for (CachedProposal cached : pendingProposals)
                    {
                        if (Arrays.equals(cached.proposalRef, id.reference))
                        {
                            out.add(cached);
                            break;
                        }
                    }
//                    out.add(null);
                    break;
            }
        }
        return out;
    }

    private GroupContext getGroupContext() throws Exception
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
                        out.add(new KeyScheduleEpoch.PSKWithSecret(psk, new Secret(resumptionPSKs.get(key))));
                    }
                    break;
            }
        }
        return out;
    }
}
