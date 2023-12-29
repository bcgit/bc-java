//package org.bouncycastle.mls.client;
//
//import com.google.protobuf.ByteString;
//import io.grpc.Status;
//import mls_client.MlsClient;
//import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
//import org.bouncycastle.mls.KeyScheduleEpoch;
//import org.bouncycastle.mls.TreeKEM.LeafIndex;
//import org.bouncycastle.mls.TreeKEM.LeafNode;
//import org.bouncycastle.mls.TreeKEM.LifeTime;
//import org.bouncycastle.mls.TreeKEM.TreeKEMPublicKey;
//import org.bouncycastle.mls.codec.Capabilities;
//import org.bouncycastle.mls.codec.Commit;
//import org.bouncycastle.mls.codec.Credential;
//import org.bouncycastle.mls.codec.Extension;
//import org.bouncycastle.mls.codec.ExtensionType;
//import org.bouncycastle.mls.codec.ExternalSender;
//import org.bouncycastle.mls.codec.GroupInfo;
//import org.bouncycastle.mls.codec.KeyPackage;
//import org.bouncycastle.mls.codec.MLSInputStream;
//import org.bouncycastle.mls.codec.MLSMessage;
//import org.bouncycastle.mls.codec.MLSOutputStream;
//import org.bouncycastle.mls.codec.PreSharedKeyID;
//import org.bouncycastle.mls.codec.Proposal;
//import org.bouncycastle.mls.codec.ProtocolVersion;
//import org.bouncycastle.mls.codec.PublicMessage;
//import org.bouncycastle.mls.codec.ResumptionPSKUsage;
//import org.bouncycastle.mls.codec.Sender;
//import org.bouncycastle.mls.codec.SenderType;
//import org.bouncycastle.mls.codec.Welcome;
//import org.bouncycastle.mls.codec.WireFormat;
//import org.bouncycastle.mls.crypto.CipherSuite;
//import org.bouncycastle.mls.crypto.Secret;
//import org.bouncycastle.util.Pack;
//import org.bouncycastle.util.encoders.Hex;
//
//import java.io.IOException;
//import java.security.SecureRandom;
//import java.util.ArrayList;
//import java.util.Arrays;
//import java.util.HashMap;
//import java.util.List;
//import java.util.Map;
//
//public class Client
//{
//    class CachedGroup {
//        Group group;
//        boolean encryptHandshake;
//        Group.MessageOptions messageOptions;
//
//        byte[] pendingCommit;
//        int pendingGroupID;
//
//        public CachedGroup(Group group, boolean encryptHandshake)
//        {
//            this.group = group;
//            this.encryptHandshake = encryptHandshake;
//        }
//
//        public void resetPending()
//        {
//            pendingCommit = null;
//            pendingGroupID = -1;
//        }
//    }
//    class CachedJoin {
//        KeyPackageWithSecrets kpSecrets;
//        Map<Secret, byte[]> externalPsks;
//
//        public CachedJoin(KeyPackageWithSecrets kpSecrets)
//        {
//            this.kpSecrets = kpSecrets;
//            this.externalPsks = new HashMap<>();
//        }
//    }
//    class CachedReinit {
//        KeyPackageWithSecrets kpSk;
//        Group.Tombstone tombstone;
//        boolean encryptHandshake;
//
//        public CachedReinit(KeyPackageWithSecrets kpSk, Group.Tombstone tombstone, boolean encryptHandshake)
//        {
//            this.kpSk = kpSk;
//            this.tombstone = tombstone;
//            this.encryptHandshake = encryptHandshake;
//        }
//    }
//    Map<Integer, CachedGroup> groupCache;
//    Map<Integer, CachedJoin> joinCache;
//    Map<Integer, CachedReinit> reinitCache;
//    Map<Integer, byte[]> signerCache;
//    KeyPackage keyPackage;
//    KeyScheduleEpoch member;
//    Group group;
//
//    KeyPackage getKeyPackage()
//    {
//        return keyPackage;
//    }
//
//    public Client()
//    {
//    }
//
//    private int storeGroup(Group group, boolean encryptHandshake)
//    {
//        int groupID = Pack.littleEndianToInt(group.getEpochAuthenticator(), 0);
//        groupID += group.getIndex().value();
//
//        CachedGroup entry = new CachedGroup(group, encryptHandshake);
//        groupCache.put(groupID, entry);
//        return groupID;
//    }
//
//    private CachedGroup loadGroup(int stateID)
//    {
//        if (!groupCache.containsKey(stateID))
//        {
//            return null;
//        }
//        return groupCache.get(stateID);
//    }
//
//    private int storeJoin(KeyPackageWithSecrets kpSecrets) throws IOException
//    {
//        CipherSuite suite = new CipherSuite(keyPackage.cipher_suite);
//        int joinID = Pack.littleEndianToInt(suite.refHash(MLSOutputStream.encode(kpSecrets.keyPackage), "MLS 1.0 KeyPackage Reference"), 0);
//        CachedJoin entry = new CachedJoin(kpSecrets);
//        joinCache.put(joinID, entry);
//        return joinID;
//    }
//
//    private CachedJoin loadJoin(int joinID)
//    {
//        if (!joinCache.containsKey(joinID))
//        {
//            return null;
//        }
//        return joinCache.get(joinID);
//    }
//
//    private int storeSigner(byte[] sigPub)
//    {
//        int signerID = Pack.littleEndianToInt(sigPub, 0);
//        signerCache.put(signerID, sigPub);
//        return signerID;
//    }
//
//    private byte[] loadSigner(int signerID)
//    {
//        if (!signerCache.containsKey(signerID))
//        {
//            return null;
//        }
//        return signerCache.get(signerID);
//    }
//
//    private int storeReinit(KeyPackageWithSecrets kpSk, Group.Tombstone tombstone, boolean encryptHandshake) throws IOException
//    {
//        CipherSuite suite = new CipherSuite(kpSk.keyPackage.cipher_suite);
//        int reinitID = Pack.littleEndianToInt(suite.refHash(MLSOutputStream.encode(kpSk.keyPackage), "MLS 1.0 KeyPackage Reference"), 0);
//
//        reinitCache.put(reinitID, new CachedReinit(kpSk, tombstone, encryptHandshake));
//        return reinitID;
//    }
//
//    private CachedReinit loadReinit(int reinitID)
//    {
//        if (!reinitCache.containsKey(reinitID))
//        {
//            return null;
//        }
//        return reinitCache.get(reinitID);
//    }
//
//    public Status createGroup(MlsClient.CreateGroupRequest request, MlsClient.CreateGroupResponse response)
//            throws Exception
//    {
//        byte[] groupID = request.getGroupId().toByteArray();
//        CipherSuite suite = new CipherSuite((short)request.getCipherSuite());
//        byte[] identity = request.getIdentity().toByteArray();
//
//        AsymmetricCipherKeyPair leafKeyPair = suite.getHPKE().generatePrivateKey();
//        AsymmetricCipherKeyPair sigKeyPair = suite.generateSignatureKeyPair();
//        Credential cred = Credential.forBasic(identity);
//
//        LeafNode leafNode = new LeafNode(
//                suite,
//                suite.getHPKE().serializePublicKey(leafKeyPair.getPublic()),
//                suite.serializeSignaturePublicKey(sigKeyPair.getPublic()),
//                cred,
//                new Capabilities(),
//                new LifeTime(),
//                new ArrayList<>(),
//                suite.serializeSignaturePrivateKey(sigKeyPair.getPrivate())
//        );
//        Group group = new Group(
//                groupID,
//                suite,
//                leafKeyPair,
//                suite.serializeSignaturePrivateKey(sigKeyPair.getPrivate()),
//                leafNode,
//                new ArrayList<>()
//        );
//
//        int stateId = storeGroup(group, request.getEncryptHandshake());
//
//        //TODO: check if this is the right way to update response
//        response.toBuilder().
//                setStateId(stateId).build();
//
//        return Status.OK;
//    }
//
//    public Status createKeyPackage(MlsClient.CreateKeyPackageRequest request, MlsClient.CreateKeyPackageResponse response) throws Exception
//    {
//        CipherSuite suite = new CipherSuite((short)request.getCipherSuite());
//        byte[] identity = request.getIdentity().toByteArray();
//
//        KeyPackageWithSecrets kpSecrets = newKeyPackage(suite, identity);
//
//        int joinID = storeJoin(kpSecrets);
//        response.toBuilder()
//            .setInitPriv(ByteString.copyFrom(suite.getHPKE().serializePrivateKey(kpSecrets.initKeyPair.getPrivate())))
//            .setEncryptionPriv(ByteString.copyFrom(suite.getHPKE().serializePrivateKey(kpSecrets.encryptionKeyPair.getPrivate())))
//            .setSignaturePriv(ByteString.copyFrom(suite.serializeSignaturePrivateKey(kpSecrets.signatureKeyPair.getPrivate())))
//            .setKeyPackage(ByteString.copyFrom(MLSOutputStream.encode(MLSMessage.keyPackage(kpSecrets.keyPackage))))
//            .setTransactionId(joinID)
//            .build();
//
//        return Status.OK;
//    }
//
//    private KeyPackageWithSecrets newKeyPackage(CipherSuite suite, byte[] identity) throws Exception
//    {
//        AsymmetricCipherKeyPair initKeyPair = suite.getHPKE().generatePrivateKey();
//        AsymmetricCipherKeyPair leafKeyPair = suite.getHPKE().generatePrivateKey();
//        AsymmetricCipherKeyPair sigKeyPair = suite.generateSignatureKeyPair();
//        Credential cred = Credential.forBasic(identity);
//
//        LeafNode leafNode = new LeafNode(
//                suite,
//                suite.getHPKE().serializePublicKey(leafKeyPair.getPublic()),
//                suite.serializeSignaturePublicKey(sigKeyPair.getPublic()),
//                cred,
//                new Capabilities(),
//                new LifeTime(),
//                new ArrayList<>(),
//                suite.serializeSignaturePrivateKey(sigKeyPair.getPrivate())
//        );
//
//        KeyPackage kp = new KeyPackage(
//                suite,
//                suite.getHPKE().serializePublicKey(initKeyPair.getPublic()),
//                leafNode,
//                new ArrayList<>(),
//                suite.serializeSignaturePublicKey(sigKeyPair.getPublic())
//        );
//        return new KeyPackageWithSecrets(initKeyPair, leafKeyPair, sigKeyPair, kp);
//        //TODO: cache transactions?
//        // return key package as byte string/array?
//    }
//
//    public Status joinGroup(MlsClient.JoinGroupRequest request, MlsClient.JoinGroupResponse response) throws Exception
//    {
//        CachedJoin join = loadJoin(request.getTransactionId());
//        if (join == null)
//        {
//            throw new Exception("Unkown transaction ID");
//        }
//
//        Welcome welcome = (Welcome) MLSInputStream.decode(request.getWelcome().toByteArray(), Welcome.class);
//
//        TreeKEMPublicKey ratchetTree = (TreeKEMPublicKey) MLSInputStream.decode(request.getRatchetTree().toByteArray(), TreeKEMPublicKey.class);
//        CipherSuite suite = new CipherSuite(welcome.cipher_suite);
//        Group group = new Group(
//                suite.getHPKE().serializePrivateKey(join.kpSecrets.initKeyPair.getPrivate()),
//                join.kpSecrets.encryptionKeyPair,
//                suite.serializeSignaturePrivateKey(join.kpSecrets.signatureKeyPair.getPrivate()),
//                join.kpSecrets.keyPackage,
//                welcome,
//                ratchetTree,
//                join.externalPsks,
//                new HashMap<>()
//        );
//        byte[] epochAuthenticator = group.getEpochAuthenticator();
//        int stateID = storeGroup(group, request.getEncryptHandshake());
//
//        response.toBuilder()
//                .setStateId(stateID)
//                .setEpochAuthenticator(ByteString.copyFrom(epochAuthenticator))
//                .build();
//        return Status.OK;
//    }
//
//    public Status externalJoin(MlsClient.ExternalJoinRequest request, MlsClient.ExternalJoinResponse response) throws Exception
//    {
//        GroupInfo groupInfo = (GroupInfo) MLSInputStream.decode(request.getGroupInfo().toByteArray(), GroupInfo.class);
//        CipherSuite suite = new CipherSuite(groupInfo.groupContext.ciphersuite);//TODO: replace with static cipher suite obj
//
//        AsymmetricCipherKeyPair initKeyPair = suite.getHPKE().generatePrivateKey();
//        AsymmetricCipherKeyPair leafKeyPair = suite.getHPKE().generatePrivateKey();
//        AsymmetricCipherKeyPair sigKeyPair = suite.generateSignatureKeyPair();
//        byte[] identity = request.getIdentity().toByteArray();
//        Credential cred = Credential.forBasic(identity);
//
//        LeafNode leafNode = new LeafNode(
//                suite,
//                suite.getHPKE().serializePublicKey(leafKeyPair.getPublic()),
//                suite.serializeSignaturePublicKey(sigKeyPair.getPublic()),
//                cred,
//                new Capabilities(),
//                new LifeTime(),
//                new ArrayList<>(),
//                suite.serializeSignaturePrivateKey(sigKeyPair.getPrivate())
//        );
//
//        KeyPackage kp = new KeyPackage(
//                suite,
//                suite.getHPKE().serializePublicKey(initKeyPair.getPublic()),
//                leafNode,
//                new ArrayList<>(),
//                suite.serializeSignaturePublicKey(sigKeyPair.getPublic())
//        );
//
//        TreeKEMPublicKey ratchetTree = (TreeKEMPublicKey) MLSInputStream.decode(request.getRatchetTree().toByteArray(), TreeKEMPublicKey.class);
//
//        int removeIndex = -1;
//        boolean removePrior = request.getRemovePrior();
//        if (removePrior)
//        {
//            // same as importTree()
//            TreeKEMPublicKey outTree = null;
//            for (Extension ext : groupInfo.extensions)
//            {
//                outTree = ext.getRatchetTree();
//                if (outTree != null)
//                {
//                    break;
//                }
//            }
//            if (ratchetTree != null)
//            {
//                //TODO: check if it should be a deep copy
//                outTree = ratchetTree;
//            }
//            else if (outTree == null)
//            {
//                throw new Exception("No tree available");
//            }
//
//            // Scan through to find a matching identity
//            for (int i = 0; i < outTree.size.leafCount(); i++)
//            {
//                LeafIndex index = new LeafIndex(i);
//                LeafNode leaf = outTree.getLeafNode(index);
//                if (leaf == null)
//                {
//                    continue;
//                }
//
//                if (Arrays.equals(identity, leaf.getCredential().getIdentity()))
//                {
//                    continue;
//                }
//                removeIndex = i;
//            }
//            if (removeIndex == -1)
//            {
//                throw new Exception("Prior appearance not found");
//            }
//        }
//        // Install PSKs
//        Map<Secret, byte[]> externalPSKs = new HashMap<>();
//        for (int i = 0; i < request.getPsksCount(); i++)
//        {
//            MlsClient.PreSharedKey psk = request.getPsks(i);
//            Secret pskID = new Secret(psk.getPskId().toByteArray());
//            byte[] pskSecret = psk.getPskSecret().toByteArray();
//            externalPSKs.put(pskID, pskSecret);
//        }
//
//        byte[] leafSecret = new byte[suite.getKDF().getHashLength()];
//        SecureRandom random = new SecureRandom();
//        random.nextBytes(leafSecret);
//
//        Group.GroupWithMessage gwm = Group.externalJoin(
//                new Secret(leafSecret),
//                sigKeyPair,
//                kp,
//                groupInfo,
//                ratchetTree,
//                new Group.MessageOptions(false, new byte[0], 0),// FOR external join ignore encryptHandshake!
//                new LeafIndex(removeIndex),
//                externalPSKs
//        );
//
//        int stateID = storeGroup(gwm.group, request.getEncryptHandshake());
//        response.toBuilder()
//                .setStateId(stateID)
//                .setCommit(ByteString.copyFrom(MLSOutputStream.encode(gwm.message)))
//                .setEpochAuthenticator(ByteString.copyFrom(gwm.group.getEpochAuthenticator()))
//                .build();
//
//        return Status.OK;
//    }
//
//    public Status groupInfo(CachedGroup entry, MlsClient.GroupInfoRequest request, MlsClient.GroupInfoResponse response) throws Exception
//    {
//        boolean inlineTree = request.getExternalTree();
//        GroupInfo groupInfo = entry.group.getGroupInfo(inlineTree);
//        if (!inlineTree)
//        {
//            response.toBuilder()
//                    .setRatchetTree(ByteString.copyFrom(MLSOutputStream.encode(entry.group.tree)))
//                    .build();
//        }
//        return Status.OK;
//    }
//
//    public Status stateAuth(CachedGroup entry, MlsClient.StateAuthRequest request, MlsClient.StateAuthResponse response)
//    {
//        response.toBuilder()
//                .setStateAuthSecret(ByteString.copyFrom(entry.group.getEpochAuthenticator()))
//                .build();
//        return Status.OK;
//    }
//
//    public Status doExport(CachedGroup entry, MlsClient.ExportRequest request, MlsClient.ExportResponse response) throws IOException
//    {
//        String label = request.getLabel();
//        byte[] context = request.getContext().toByteArray();
//        int size = request.getKeyLength();
//        byte[] secret = entry.group.keySchedule.MLSExporter(label, context, size);
//        response.toBuilder()
//                .setExportedSecret(ByteString.copyFrom(secret))
//                .build();
//        return Status.OK;
//    }
//
//    public Status protect(CachedGroup entry, MlsClient.ProtectRequest request, MlsClient.ProtectResponse response) throws Exception
//    {
//
//        MLSMessage ct = entry.group.protect(
//                request.getAuthenticatedData().toByteArray(),
//                request.getPlaintext().toByteArray(),
//                0
//        );
//        response.toBuilder()
//                .setCiphertext(ByteString.copyFrom(MLSOutputStream.encode(ct)))
//                .build();
//        return Status.OK;
//    }
//
//    public Status unprotect(CachedGroup entry, MlsClient.UnprotectRequest request, MlsClient.UnprotectResponse response) throws Exception
//    {
//        MLSMessage ct = (MLSMessage) MLSInputStream.decode(request.getCiphertext().toByteArray(), MLSMessage.class);
//
//        // Locate the right epoch to decrypt with
//        byte[] groupID = entry.group.getGroupID();
//        long epoch = ct.getEpoch();
//        Group group = null;
//        if (entry.group.getEpoch() != epoch)
//        {
//            CachedGroup cached = findState(groupID, epoch);
//            if (cached == null)
//            {
//                throw new Exception("Unknown state for unprotect");
//            }
//            group = cached.group;
//        }
//
//        // Decrypt the message
//        byte[][] authAndPt = group.unprotect(ct);
//        byte[] aad = authAndPt[0];
//        byte[] pt = authAndPt[1];
//
//        response.toBuilder()
//                .setAuthenticatedData(ByteString.copyFrom(aad))
//                .setPlaintext(ByteString.copyFrom(pt))
//                .build();
//
//        return Status.OK;
//    }
//
//    private CachedGroup findState(byte[] groupID, long epoch)
//    {
//        CachedGroup result = null;
//        for (int id : groupCache.keySet())
//        {
//            CachedGroup cached = groupCache.get(id);
//            if (cached != null && Arrays.equals(cached.group.getGroupID(), groupID) && cached.group.getEpoch() == epoch)
//            {
//                result = cached;
//            }
//        }
//        return result;
//    }
//
//    public Status addProposal(CachedGroup entry, MlsClient.AddProposalRequest request, MlsClient.ProposalResponse response) throws Exception
//    {
//        KeyPackage keyPackage = (KeyPackage) MLSInputStream.decode(request.getKeyPackage().toByteArray(), KeyPackage.class);
//        MLSMessage message = entry.group.add(keyPackage, entry.messageOptions);
//
//        response.toBuilder()
//                .setProposal(ByteString.copyFrom(MLSOutputStream.encode(message)))
//                .build();
//
//        return Status.OK;
//    }
//
//    public Status updateProposal(CachedGroup entry, MlsClient.UpdateProposalRequest request, MlsClient.ProposalResponse response) throws Exception
//    {
//
//        AsymmetricCipherKeyPair leafSk = entry.group.suite.generateSignatureKeyPair();
//        Proposal update = entry.group.updateProposal(leafSk, null);
//        MLSMessage message = entry.group.update(update, entry.messageOptions);
//
//        response.toBuilder()
//                .setProposal(ByteString.copyFrom(MLSOutputStream.encode(message)))
//                .build();
//
//        return Status.OK;
//    }
//
//    public Status removeProposal(CachedGroup entry, MlsClient.RemoveProposalRequest request, MlsClient.ProposalResponse response) throws Exception
//    {
//        LeafIndex removedIndex = findMember(entry.group.tree, request.getRemovedId().toByteArray());
//        MLSMessage message = entry.group.remove(removedIndex, entry.messageOptions);
//
//        response.toBuilder()
//                .setProposal(ByteString.copyFrom(MLSOutputStream.encode(message)))
//                .build();
//
//        return Status.OK;
//    }
//
//    public Status externalPskProposal(CachedGroup entry, MlsClient.ExternalPSKProposalRequest request, MlsClient.ProposalResponse response) throws Exception
//    {
//        byte[] pskID = request.getPskId().toByteArray();
//        MLSMessage message = entry.group.preSharedKey(pskID, entry.messageOptions);
//
//        response.toBuilder()
//                .setProposal(ByteString.copyFrom(MLSOutputStream.encode(message)))
//                .build();
//
//        return Status.OK;
//    }
//
//    public Status resumptionPskProposal(CachedGroup entry, MlsClient.ResumptionPSKProposalRequest request, MlsClient.ProposalResponse response) throws Exception
//    {
//
//        MLSMessage message = entry.group.preSharedKey(entry.group.getGroupID(), request.getEpochId(), entry.messageOptions);
//
//        response.toBuilder()
//                .setProposal(ByteString.copyFrom(MLSOutputStream.encode(message)))
//                .build();
//
//        return Status.OK;
//    }
//
//    public Status commit(CachedGroup entry, MlsClient.CommitRequest request, MlsClient.CommitResponse response) throws Exception
//    {
//        int byRefSize = request.getByReferenceCount();
//        for (int i = 0; i < byRefSize; i++)
//        {
//            byte[] msg = request.getByReference(i).toByteArray();
//            Group shouldBeNull = entry.group.handle(msg, null);
//            if (shouldBeNull != null)
//            {
//                throw new Exception("Commit included among proposals");
//            }
//        }
//
//        // create by value proposals
//        List<Proposal> byValue = new ArrayList<>();
//        for (int i = 0; i < request.getByValueCount(); i++)
//        {
//            MlsClient.ProposalDescription desc = request.getByValue(i);
//            Proposal proposal = proposalFromDescription(
//                    entry.group.suite,
//                    entry.group.getGroupID(),
//                    entry.group.tree,
//                    desc
//            );
//            byValue.add(proposal);
//        }
//
//        boolean forcePath = request.getForcePath();
//        boolean inlineTree = !request.getExternalTree();
//
//        SecureRandom random = new SecureRandom();
//        byte[] leafSecret = new byte[entry.group.suite.getKDF().getHashLength()];
//        random.nextBytes(leafSecret);
//        Group.GroupWithMessage gwm = entry.group.commit(
//                new Secret(leafSecret),
//                new Group.CommitOptions(byValue, inlineTree, forcePath, null),
//                entry.messageOptions,
//                null
//        );
//        byte[] commitBytes = MLSOutputStream.encode(gwm.message);
//        gwm.message.wireFormat = WireFormat.mls_welcome;
//        byte[] welcomeBytes = MLSOutputStream.encode(gwm.message);
//
//        //TODO: check if entry.group should/shouldn't be replaced by commit()
//        int nextID = storeGroup(gwm.group, entry.encryptHandshake);
//
//        entry.pendingCommit = commitBytes;
//        entry.pendingGroupID = nextID;
//
//        response.toBuilder()
//                .setRatchetTree(!inlineTree ? ByteString.copyFrom(MLSOutputStream.encode(gwm.group.tree)) : null)
//                .setCommit(ByteString.copyFrom(commitBytes))
//                .setWelcome(ByteString.copyFrom(welcomeBytes))
//                .build();
//
//        return Status.OK;
//    }
//
//    private Proposal proposalFromDescription(CipherSuite suite, byte[] groupID, TreeKEMPublicKey tree, MlsClient.ProposalDescription desc) throws Exception
//    {
//        SecureRandom random = new SecureRandom();
//        switch (desc.getProposalType().toString())
//        {
//            case "add":
//                KeyPackage kp = (KeyPackage) MLSInputStream.decode(desc.getKeyPackage().toByteArray(), KeyPackage.class);
//                return Proposal.add(kp);
//
//            case "remove":
//                LeafIndex removedIndex = findMember(tree, desc.getRemovedId().toByteArray());
//                return Proposal.remove(removedIndex);
//
//            case "externalPSK":
//                byte[] externalPskID = desc.getPskId().toByteArray();
//                byte[] extNonce = new byte[suite.getKDF().getHashLength()];
//                random.nextBytes(extNonce);
//                PreSharedKeyID extPskID = PreSharedKeyID.external(externalPskID, extNonce);
//                return Proposal.preSharedKey(extPskID);
//
//            case "resumptionPSK":
//                long epoch = desc.getEpochId();
//                byte[] resNonce = new byte[suite.getKDF().getHashLength()];
//                PreSharedKeyID resPskID = PreSharedKeyID.resumption(ResumptionPSKUsage.APPLICATION, groupID, epoch, resNonce);
//                return Proposal.preSharedKey(resPskID);
//
//            case "groupContextExtensions":
//            case "reinit":
//                List<Extension> extList = new ArrayList<>();
//                for (int i = 0; i < desc.getExtensionsCount(); i++)
//                {
////                    MlsClient.Extension ext = desc.getExtensions(i);
////                    extList.add(new Extension(ext.getExtensionType(), ext.getExtensionData().toByteArray()));
//                    Extension ext = (Extension) MLSInputStream.decode(desc.getExtensions(i).toByteArray(), Extension.class);
//                    extList.add(ext);
//                }
//
//                if (desc.getProposalType().toString().equals("reinit"))
//                {
//                    return Proposal.reInit(
//                            desc.getGroupId().toByteArray(),
//                            ProtocolVersion.mls10,
//                            (short) desc.getCipherSuite(),
//                            extList
//                    );
//                }
//                // groupContextExtensions
//                return Proposal.groupContextExtensions(extList);
//
//            default:
//                throw new IllegalStateException("Unknown proposal-by-value type: " + desc.getProposalType().toString());
//        }
//    }
//
//    private void removeGroup(int stateID)
//    {
//        groupCache.remove(stateID);
//    }
//
//    public Status handleCommit(CachedGroup entry, MlsClient.HandleCommitRequest request, MlsClient.HandleCommitResponse response) throws Exception
//    {
//        // Handle our own commits with caching
//        byte[] commitBytes = request.getCommit().toByteArray();
//        if (entry.pendingCommit != null && Arrays.equals(commitBytes, entry.pendingCommit))
//        {
//            response.toBuilder()
//                    .setStateId(entry.pendingGroupID)
//                    .build();
//            entry.resetPending();
//            return Status.OK;
//        }
//        else if (entry.pendingGroupID != -1)
//        {
//            removeGroup(entry.pendingGroupID);
//            entry.resetPending();
//        }
//
//        int proposalSize = request.getProposalCount();
//        for (int i = 0; i < proposalSize; i++)
//        {
//            byte[] messageBytes = request.getProposal(i).toByteArray();
//            Group shouldBeNull = group.handle(messageBytes, null);
//            if (shouldBeNull != null)
//            {
//                throw new Exception("Commit included among proposals");
//            }
//        }
//
//        Group next = group.handle(commitBytes, null);
//        if (next == null)
//        {
//            throw new Exception("Commit failed to produce a new state");
//        }
//
//        byte[] epochAuthenticator = next.getEpochAuthenticator();
//        int nextID = storeGroup(next, entry.encryptHandshake);
//
//        response.toBuilder()
//                .setStateId(nextID)
//                .setEpochAuthenticator(ByteString.copyFrom(epochAuthenticator))
//                .build();
//
//        return Status.OK;
//    }
//
//    public Status handlePendingCommit(CachedGroup entry, MlsClient.HandlePendingCommitRequest request, MlsClient.HandleCommitResponse response) throws Exception
//    {
//        if (entry.pendingCommit == null || entry.pendingGroupID == -1)
//        {
//            throw new Exception("No pending commit to handle");
//        }
//
//        int nextID = entry.pendingGroupID;
//        CachedGroup next = loadGroup(nextID);
//        if (next == null)
//        {
//            throw new Exception("No Internal error: No state for next ID");
//        }
//
//        byte[] epochAuthenticator = next.group.getEpochAuthenticator();
//        response.toBuilder()
//                .setStateId(nextID)
//                .setEpochAuthenticator(ByteString.copyFrom(epochAuthenticator))
//                .build();
//
//        return Status.OK;
//    }
//
//    public Status newMemberAddProposal(MlsClient.NewMemberAddProposalRequest request, MlsClient.NewMemberAddProposalResponse response) throws Exception
//    {
//        GroupInfo groupInfo = (GroupInfo) MLSInputStream.decode(request.getGroupInfo().toByteArray(), GroupInfo.class);
//        CipherSuite suite = new CipherSuite(groupInfo.groupContext.ciphersuite);
//
//        KeyPackageWithSecrets kpSk = newKeyPackage(suite, request.getIdentity().toByteArray());
//
//        byte[] initSk =  suite.getHPKE().serializePrivateKey(kpSk.initKeyPair.getPrivate());
//        byte[] encryptionSk = suite.getHPKE().serializePrivateKey(kpSk.encryptionKeyPair.getPrivate());
//        byte[] signatureSk = suite.serializeSignaturePrivateKey(kpSk.signatureKeyPair.getPrivate());
//
//        PublicMessage proposal = Group.newMemberAdd(
//                groupInfo.groupContext.groupID,
//                groupInfo.groupContext.epoch,
//                kpSk.keyPackage,
//                kpSk.signatureKeyPair
//        );
//
//        int joinID = storeJoin(kpSk);
//
//        response.toBuilder()
//                .setInitPriv(ByteString.copyFrom(initSk))
//                .setEncryptionPriv(ByteString.copyFrom(encryptionSk))
//                .setSignaturePriv(ByteString.copyFrom(signatureSk))
//                .setProposal(ByteString.copyFrom(MLSOutputStream.encode(proposal)))
//                .setTransactionId(joinID)
//                .build();
//
//        return Status.OK;
//    }
//
//    public Status createExternalSinger(MlsClient.CreateExternalSignerRequest request, MlsClient.CreateExternalSignerResponse response) throws IOException
//    {
//        CipherSuite suite = new CipherSuite((short)request.getCipherSuite());
//        AsymmetricCipherKeyPair sigSk = suite.generateSignatureKeyPair();
//        Credential cred = Credential.forBasic(request.getIdentity().toByteArray());
//
//        ExternalSender extSender = new ExternalSender(suite.serializeSignaturePublicKey(sigSk.getPublic()), cred);
//
//        int signerID = storeSigner(suite.serializeSignaturePublicKey(sigSk.getPublic()));
//
//        response.toBuilder()
//                .setExternalSender(ByteString.copyFrom(MLSOutputStream.encode(extSender)))
//                .setSignerId(signerID)
//                .build();
//
//        return Status.OK;
//    }
//
//    public Status addExternalSigner(CachedGroup entry, MlsClient.AddExternalSignerRequest request, MlsClient.ProposalResponse response) throws IOException
//    {
//        byte[] extSender = request.getExternalSender().toByteArray();
//
//        List<Extension> extList = entry.group.extensions;
//        List<ExternalSender> extSenders = new ArrayList<>();
//        for (Extension ext : extList)
//        {
//            if (ext.extensionType == ExtensionType.EXTERNAL_SENDERS)
//            {
//                extSenders = ext.getSenders();
//            }
//        }
//        extSenders.add((ExternalSender) MLSInputStream.decode(extSender, MLSInputStream.class));
//        extList.add(Extension.externalSender(extSenders));
//
//        Proposal proposal = Proposal.groupContextExtensions(extList);
//        response.toBuilder()
//                .setProposal(ByteString.copyFrom(MLSOutputStream.encode(proposal)))
//                .build();
//
//        return Status.OK;
//    }
//
//    public Status externalSignerProposal(MlsClient.ExternalSignerProposalRequest request, MlsClient.ProposalResponse response) throws Exception
//    {
//        byte[] groupMsgData = request.getGroupInfo().toByteArray();
//        MLSMessage groupMsg = (MLSMessage) MLSInputStream.decode(groupMsgData, MLSMessage.class);
//        GroupInfo groupInfo = groupMsg.groupInfo;
//
//        CipherSuite suite = new CipherSuite(groupInfo.groupContext.ciphersuite);
//        byte[] groupID = groupInfo.groupContext.groupID;
//        long epoch = groupInfo.groupContext.epoch;
//
//        byte[] treeData = request.getRatchetTree().toByteArray();
//        TreeKEMPublicKey tree = (TreeKEMPublicKey) MLSInputStream.decode(treeData, TreeKEMPublicKey.class);
//
//        // Look up the signer
//        byte[] signer = loadSigner(request.getSignerId());
//        if (signer == null)
//        {
//            throw new Exception("Unknown signer ID");
//        }
//
//        // Look up the signer index of this signer
//        List<ExternalSender> extSenders = new ArrayList<>();
//        for (Extension ext : groupInfo.groupContext.extensions)
//        {
//            if (ext.extensionType == ExtensionType.EXTERNAL_SENDERS)
//            {
//                extSenders = ext.getSenders();
//            }
//        }
//        int sigIndex = -1;
//        for (int i = 0; i < extSenders.size(); i++)
//        {
//            if (Arrays.equals(extSenders.get(i).signatureKey, signer))
//            {
//                sigIndex = i;
//            }
//        }
//        if (sigIndex == -1)
//        {
//            throw new Exception("Requested signer not allowed for this group");
//        }
//
//        // Sign the proposal
//        Proposal proposal = proposalFromDescription(suite, groupID, tree, request.getDescription());
//        MLSMessage signedProposal = MLSMessage.externalProposal(suite, groupID, epoch, proposal, sigIndex, signer);
//
//        response.toBuilder()
//                .setProposal(ByteString.copyFrom(MLSOutputStream.encode(signedProposal)))
//                .build();
//
//        return Status.OK;
//    }
//
//    public Status reinitProposal(CachedGroup entry, MlsClient.ReInitProposalRequest request, MlsClient.ProposalResponse response) throws Exception
//    {
//        byte[] groupID = request.getGroupId().toByteArray();
//        ProtocolVersion version = ProtocolVersion.mls10;
//        CipherSuite suite = new CipherSuite((short) request.getCipherSuite());
//
//        List<Extension> extList = new ArrayList<>();
//        for (int i = 0; i < request.getExtensionsCount(); i++)
//        {
////            MlsClient.Extension ext = request.getExtensions(i);
////            extList.add(new Extension(ext.getExtensionType(), ext.getExtensionData().toByteArray()));
//            extList.add((Extension) MLSInputStream.decode(request.getExtensions(i).toByteArray(), Extension.class));
//        }
//
//        MLSMessage message = entry.group.reinit(groupID, version, suite, extList, entry.messageOptions);
//        response.toBuilder()
//                .setProposal(ByteString.copyFrom(MLSOutputStream.encode(message)))
//                .build();
//
//        return Status.OK;
//    }
//
//    public Status reinitCommit(CachedGroup entry, MlsClient.CommitRequest request, MlsClient.CommitResponse response) throws Exception
//    {
//        boolean inlineTree = !request.getExternalTree();
//        boolean forcePath = request.getForcePath();
//
//        // For now ReInit proposal must be provided by reference
//        if (request.getByReferenceCount() != 1)
//        {
//            throw new Exception("Malformed ReInit CommitRequest");
//        }
//        byte[] reinitProposal = request.getByReference(0).toByteArray();
//        Group shouldBeNull = entry.group.handle(reinitProposal, null);
//        if (shouldBeNull != null)
//        {
//            throw new Exception("Commit included among proposals");
//        }
//
//        SecureRandom random = new SecureRandom();
//        byte[] leafSecret = new byte[entry.group.suite.getKDF().getHashLength()];
//        random.nextBytes(leafSecret);
//        Group.CommitOptions commitOptions = new Group.CommitOptions(new ArrayList<>(), inlineTree, forcePath, null);
//        Group.TombstoneWithMessage twm = entry.group.reinitCommit(leafSecret, commitOptions, entry.messageOptions);
//
//        // cache the reinit
//        LeafNode leaf = entry.group.tree.getLeafNode(entry.group.getIndex());
//        byte[] identity = leaf.getCredential().getIdentity();
//        KeyPackageWithSecrets kpSk = newKeyPackage(new CipherSuite(twm.reinit.cipherSuite), identity);;
//        int reinitID = storeReinit(kpSk, twm, entry.encryptHandshake);
//        byte[] commitBytes = MLSOutputStream.encode(twm.message);
//
//        response.toBuilder()
//                .setCommit(ByteString.copyFrom(commitBytes))
//                .build();
//
//        entry.pendingCommit = commitBytes;
//        entry.pendingGroupID = reinitID;
//
//        return Status.OK;
//    }
//
//    public Status handleReinitCommit(CachedGroup entry, MlsClient.HandleCommitRequest request, MlsClient.HandleReInitCommitResponse response) throws Exception
//    {
//        //TODO: Reinit proposal must be provided by reference for now
//        if (request.getProposalCount() != 1)
//        {
//            throw new Exception("Malformed ReInit CommitRequest");
//        }
//        byte[] reinitMessage = request.getProposal(0).toByteArray();
//        Group shouldBeNull = entry.group.handle(reinitMessage, null);
//        if (shouldBeNull != null)
//        {
//            throw new Exception("Commit included among proposals");
//        }
//
//        MLSMessage commit = (MLSMessage) MLSInputStream.decode(request.getCommit().toByteArray(), MLSMessage.class);
//        Group.Tombstone tombstone = entry.group.handleReinitCommit(commit);
//
//        // Cache the reinit
//        LeafNode leafNode = entry.group.tree.getLeafNode(entry.group.getIndex());
//        byte[] identity = leafNode.getCredential().getIdentity();
//        KeyPackageWithSecrets kpSk = newKeyPackage(new CipherSuite(tombstone.reinit.cipherSuite), identity);
//
//        int reinitID = storeReinit(kpSk, tombstone, entry.encryptHandshake);
//
//        response.toBuilder()
//                .setReinitId(reinitID)
//                .setKeyPackage(ByteString.copyFrom(MLSOutputStream.encode(kpSk.keyPackage)))
//                .setEpochAuthenticator(ByteString.copyFrom(tombstone.epochAuthenticator))
//                .build();
//
//        return Status.OK;
//    }
//
//    private Status reinitWelcome(MlsClient.ReInitWelcomeRequest request, MlsClient.CreateSubgroupResponse response) throws Exception
//    {
//        // Load the reinit
//        CachedReinit reinit = loadReinit(request.getReinitId());
//        if (reinit == null)
//        {
//            return Status.INVALID_ARGUMENT.withDescription("Unknown reinit ID");
//        }
//
//        // Import the KeyPackages
//        List<KeyPackage> keyPackages = new ArrayList<>();
//        for (int i = 0; i < request.getKeyPackageCount(); i++)
//        {
//            byte[] keyPackageData = request.getKeyPackage(i).toByteArray();
//            MLSMessage message = (MLSMessage) MLSInputStream.decode(keyPackageData, MLSMessage.class);
//            keyPackages.add(message.keyPackage);
//        }
//
//        // Create the Welcome
//        boolean inlineTree = !request.getExternalTree();
//        boolean forcePath = request.getForcePath();
//        CipherSuite suite = new CipherSuite(reinit.tombstone.reinit.cipherSuite);
//        byte[] leafSecret = new byte[suite.getKDF().getHashLength()];
//
//        Group.GroupWithMessage gwm = reinit.tombstone.createWelcome(
//                reinit.kpSk.encryptionKeyPair,
//                suite.serializeSignaturePrivateKey(reinit.kpSk.signatureKeyPair.getPrivate()),
//                reinit.kpSk.keyPackage.leaf_node,
//                keyPackages,
//                leafSecret,
//                new Group.CommitOptions(null, inlineTree, forcePath, null)
//        );
//        byte[] welcomeData = MLSOutputStream.encode(gwm.message);
//
//        // Store the resulting state
//        int stateID = storeGroup(gwm.group, reinit.encryptHandshake);
//        response.toBuilder()
//                .setStateId(stateID)
//                .setWelcome(ByteString.copyFrom(welcomeData))
//                .setEpochAuthenticator(ByteString.copyFrom(gwm.group.getEpochAuthenticator()))
//                .setRatchetTree(!inlineTree ? ByteString.copyFrom(MLSOutputStream.encode(gwm.group.tree)) : null)
//                .build();
//
//        return Status.OK;
//    }
//
//    public Status handleReinitWelcome(MlsClient.HandleReInitWelcomeRequest request, MlsClient.JoinGroupResponse response) throws Exception
//    {
//        // Load the reinit
//        CachedReinit reinit = loadReinit(request.getReinitId());
//        if (reinit == null)
//        {
//            return Status.INVALID_ARGUMENT.withDescription("Unknown reinit ID");
//        }
//
//        // Process the welcome
//        MLSMessage welcome = (MLSMessage) MLSInputStream.decode(request.getWelcome().toByteArray(), MLSMessage.class);
//
//        TreeKEMPublicKey ratchetTree = (TreeKEMPublicKey) MLSInputStream.decode(request.getRatchetTree().toByteArray(), TreeKEMPublicKey.class);
//
//        Group group = reinit.tombstone.handleWelcome(
//                reinit.kpSk.initKeyPair,
//                reinit.kpSk.encryptionKeyPair,
//                reinit.kpSk.signatureKeyPair,
//                reinit.kpSk.keyPackage,
//                welcome,
//                ratchetTree
//        );
//
//        // Store the resulting group
//        int stateID = storeGroup(group, reinit.encryptHandshake);
//
//        response.toBuilder()
//                .setStateId(stateID)
//                .setEpochAuthenticator(ByteString.copyFrom(group.getEpochAuthenticator()))
//                .build();
//
//        return Status.OK;
//    }
//
//    public Status createBranch(CachedGroup entry, MlsClient.CreateBranchRequest request, MlsClient.CreateSubgroupResponse response) throws Exception
//    {
//        // Import KeyPackages
//        List<KeyPackage> keyPackages = new ArrayList<>();
//        for (int i = 0; i < request.getKeyPackagesCount(); i++)
//        {
//            MLSMessage message = (MLSMessage) MLSInputStream.decode(request.getKeyPackages(i).toByteArray(), MLSMessage.class);
//            keyPackages.add(message.keyPackage);
//        }
//
//        // Import extensions
//        List<Extension> extList = new ArrayList<>();
//        for (int i = 0; i < request.getExtensionsCount(); i++)
//        {
//            Extension ext = (Extension) MLSInputStream.decode(request.getExtensions(i).toByteArray(), Extension.class);
//            extList.add(ext);
//        }
//
//        // Create the branch
//        LeafNode leaf = entry.group.tree.getLeafNode(entry.group.getIndex());
//        byte[] identity = leaf.getCredential().getIdentity();
//
//        boolean inlineTree = !request.getExternalTree();
//        boolean forcePath = request.getForcePath();
//        byte[] groupID = request.getGroupId().toByteArray();
//        CipherSuite suite = entry.group.suite;
//        KeyPackageWithSecrets kpSK = newKeyPackage(suite, identity);
//        byte[] leafSecret = new byte[suite.getKDF().getHashLength()];
//        SecureRandom random = new SecureRandom();
//        random.nextBytes(leafSecret);
//
//        Group.GroupWithMessage gwm = entry.group.createBranch(
//                groupID,
//                kpSK.encryptionKeyPair,
//                kpSK.signatureKeyPair,
//                kpSK.keyPackage.leaf_node,
//                extList,
//                keyPackages,
//                leafSecret,
//                new Group.CommitOptions(null, inlineTree, forcePath, null)
//        );
//
//        int nextID = storeGroup(gwm.group, entry.encryptHandshake);
//
//        response.toBuilder()
//                .setStateId(nextID)
//                .setWelcome(ByteString.copyFrom(MLSOutputStream.encode(gwm.message)))
//                .setEpochAuthenticator(ByteString.copyFrom(gwm.group.getEpochAuthenticator()))
//                .setRatchetTree(!inlineTree ? ByteString.copyFrom(MLSOutputStream.encode(gwm.group.tree)) : null)
//                .build();
//
//        return Status.OK;
//    }
//
//    public Status handleBranch(CachedGroup entry, MlsClient.HandleBranchRequest request, MlsClient.HandleBranchResponse response) throws Exception
//    {
//        CachedJoin join = loadJoin(request.getTransactionId());
//        if (join == null)
//        {
//            return Status.INVALID_ARGUMENT.withDescription("Unknown transaction ID");
//        }
//
//        MLSMessage welcome = (MLSMessage) MLSInputStream.decode(request.getWelcome().toByteArray(), MLSMessage.class);
//        TreeKEMPublicKey ratchetTree = (TreeKEMPublicKey) MLSInputStream.decode(request.getRatchetTree().toByteArray(), TreeKEMPublicKey.class);
//
//        Group group = entry.group.handleBranch(
//                join.kpSecrets.initKeyPair,
//                join.kpSecrets.encryptionKeyPair,
//                join.kpSecrets.signatureKeyPair,
//                join.kpSecrets.keyPackage,
//                welcome,
//                ratchetTree
//        );
//
//        int stateID = storeGroup(group, entry.encryptHandshake);
//
//        response.toBuilder()
//                .setStateId(stateID)
//                .setEpochAuthenticator(ByteString.copyFrom(group.getEpochAuthenticator()))
//                .build();
//
//        return Status.OK;
//    }
//
//    private LeafIndex findMember(TreeKEMPublicKey tree, byte[] id) throws Exception
//    {
//        //find member
//        LeafNode leaf;
//        LeafIndex index;
//        for (int i = 0; i < tree.size.leafCount() ; i++)
//        {
//            index = new LeafIndex(i);
//            leaf = tree.getLeafNode(index);
//            if (leaf == null)
//            {
//                continue;
//            }
//            if (Arrays.equals(leaf.getCredential().getIdentity(), id))
//            {
//                return index;
//            }
//        }
//        throw new Exception("Unknown member identity");
//    }
//
//
//
//
//}
