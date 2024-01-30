package org.bouncycastle.mls.client;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.protobuf.ByteString;
import com.google.protobuf.MessageOrBuilder;
import io.grpc.Status;
import io.grpc.StatusException;
import io.grpc.stub.StreamObserver;
import mls_client.MLSClientGrpc;
import mls_client.MlsClient;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.mls.TreeKEM.LeafIndex;
import org.bouncycastle.mls.TreeKEM.LeafNode;
import org.bouncycastle.mls.TreeKEM.LifeTime;
import org.bouncycastle.mls.TreeKEM.TreeKEMPublicKey;
import org.bouncycastle.mls.codec.Capabilities;
import org.bouncycastle.mls.codec.Credential;
import org.bouncycastle.mls.codec.Extension;
import org.bouncycastle.mls.codec.ExtensionType;
import org.bouncycastle.mls.codec.ExternalSender;
import org.bouncycastle.mls.codec.GroupInfo;
import org.bouncycastle.mls.codec.KeyPackage;
import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSMessage;
import org.bouncycastle.mls.codec.MLSOutputStream;
import org.bouncycastle.mls.codec.PreSharedKeyID;
import org.bouncycastle.mls.codec.Proposal;
import org.bouncycastle.mls.codec.ProtocolVersion;
import org.bouncycastle.mls.codec.ResumptionPSKUsage;
import org.bouncycastle.mls.codec.Welcome;
import org.bouncycastle.mls.codec.WireFormat;
import org.bouncycastle.mls.crypto.MlsCipherSuite;
import org.bouncycastle.mls.crypto.Secret;
import org.bouncycastle.mls.protocol.Group;
import org.bouncycastle.util.Pack;

import static org.bouncycastle.mls.crypto.MlsCipherSuite.ALL_SUPPORTED_SUITES;
import static org.bouncycastle.mls.protocol.Group.NORMAL_COMMIT_PARAMS;

public class MLSClientImpl
    extends MLSClientGrpc.MLSClientImplBase
{
    class CachedGroup
    {
        Group group;
        boolean encryptHandshake;
        Group.MessageOptions messageOptions;

        byte[] pendingCommit;
        int pendingGroupID;

        public CachedGroup(Group group, boolean encryptHandshake)
        {
            this.group = group;
            this.encryptHandshake = encryptHandshake;
            this.messageOptions = new Group.MessageOptions(encryptHandshake, new byte[0], 0);
        }

        public void resetPending()
        {
            pendingCommit = null;
            pendingGroupID = -1;
        }
    }

    class CachedJoin
    {
        KeyPackageWithSecrets kpSecrets;
        Map<Secret, byte[]> externalPsks;

        public CachedJoin(KeyPackageWithSecrets kpSecrets)
        {
            this.kpSecrets = kpSecrets;
            this.externalPsks = new HashMap<Secret, byte[]>();
        }
    }

    class CachedReinit
    {
        KeyPackageWithSecrets kpSk;
        Group.Tombstone tombstone;
        boolean encryptHandshake;

        public CachedReinit(KeyPackageWithSecrets kpSk, Group.Tombstone tombstone, boolean encryptHandshake)
        {
            this.kpSk = kpSk;
            this.tombstone = tombstone;
            this.encryptHandshake = encryptHandshake;
        }
    }

    Map<Integer, CachedGroup> groupCache = new HashMap<Integer, CachedGroup>();
    Map<Integer, CachedJoin> joinCache = new HashMap<Integer, CachedJoin>();
    Map<Integer, CachedReinit> reinitCache = new HashMap<Integer, CachedReinit>();
    Map<Integer, byte[]> signerCache = new HashMap<Integer, byte[]>();


    @FunctionalInterface
    public interface Function
    {
        void run()
            throws Exception;
    }

    @FunctionalInterface
    public interface FunctionWithState
    {
        void run(CachedGroup g)
            throws Exception;
    }

    private static String getCallerMethodName()
    {
        StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
        return stackTrace[3].getMethodName();
    }

    private static <T> void catchWrap(Function f, StreamObserver<T> observer)
    {
        try
        {
            f.run();
        }
        catch (Exception e)
        {
            observer.onError(Status.INTERNAL.withDescription(e.getMessage()).asException());
        }
    }

    private <T> void stateWrap(FunctionWithState f, MessageOrBuilder request, StreamObserver<T> observer)
    {
        int stateID = (int)request.getField(request.getDescriptorForType().findFieldByName("state_id"));
        CachedGroup group = loadGroup(stateID);
        if (group == null)
        {
            observer.onError(Status.NOT_FOUND.withDescription("Unknown state").asException());
        }
        try
        {
            f.run(group);
        }
        catch (Exception e)
        {
            observer.onError(Status.INTERNAL.withDescription(e.getMessage()).asException());
        }
    }


    private int storeGroup(Group group, boolean encryptHandshake)
    {
        int groupID = 0x07FFFFFF & Pack.littleEndianToInt(group.getEpochAuthenticator(), 0);
        groupID += group.getIndex().value();

        CachedGroup entry = new CachedGroup(group, encryptHandshake);
        groupCache.put(groupID, entry);
        return groupID;
    }

    private CachedGroup loadGroup(int stateID)
    {
        if (!groupCache.containsKey(stateID))
        {
            return null;
        }
        return groupCache.get(stateID);
    }

    private int storeJoin(KeyPackageWithSecrets kpSecrets)
        throws IOException
    {
        MlsCipherSuite suite = kpSecrets.keyPackage.getSuite();
        int joinID = 0x07FFFFFF & Pack.littleEndianToInt(suite.refHash(MLSOutputStream.encode(kpSecrets.keyPackage), "MLS 1.0 KeyPackage Reference"), 0);
        CachedJoin entry = new CachedJoin(kpSecrets);
        joinCache.put(joinID, entry);
        return joinID;
    }

    private CachedJoin loadJoin(int joinID)
    {
        if (!joinCache.containsKey(joinID))
        {
            return null;
        }
        return joinCache.get(joinID);
    }

    private int storeSigner(byte[] sigPriv)
    {
        int signerID = 0x07FFFFFF & Pack.littleEndianToInt(sigPriv, 0);
        signerCache.put(signerID, sigPriv);
        return signerID;
    }

    private byte[] loadSigner(int signerID)
    {
        if (!signerCache.containsKey(signerID))
        {
            return null;
        }
        return signerCache.get(signerID); // returns private signature key
    }

    private int storeReinit(KeyPackageWithSecrets kpSk, Group.Tombstone tombstone, boolean encryptHandshake)
        throws IOException
    {
        MlsCipherSuite suite = kpSk.keyPackage.getSuite();
        int reinitID = 0x07FFFFFF & Pack.littleEndianToInt(suite.refHash(MLSOutputStream.encode(kpSk.keyPackage), "MLS 1.0 KeyPackage Reference"), 0);

        reinitCache.put(reinitID, new CachedReinit(kpSk, tombstone, encryptHandshake));
        return reinitID;
    }

    private CachedReinit loadReinit(int reinitID)
    {
        if (!reinitCache.containsKey(reinitID))
        {
            return null;
        }
        return reinitCache.get(reinitID);
    }

    private CachedGroup findState(byte[] groupID, long epoch)
    {
        CachedGroup result = null;
        for (int id : groupCache.keySet())
        {
            CachedGroup cached = groupCache.get(id);
            if (cached != null && Arrays.equals(cached.group.getGroupID(), groupID) && cached.group.getEpoch() == epoch)
            {
                result = cached;
            }
        }
        return result;
    }

    private KeyPackageWithSecrets newKeyPackage(MlsCipherSuite suite, byte[] identity)
        throws Exception
    {
        AsymmetricCipherKeyPair initKeyPair = suite.getHPKE().generatePrivateKey();
        AsymmetricCipherKeyPair encryptionKeyPair = suite.getHPKE().generatePrivateKey();
        AsymmetricCipherKeyPair sigKeyPair = suite.generateSignatureKeyPair();
        Credential cred = Credential.forBasic(identity);

        LeafNode leafNode = new LeafNode(
            suite,
            suite.getHPKE().serializePublicKey(encryptionKeyPair.getPublic()),
            suite.serializeSignaturePublicKey(sigKeyPair.getPublic()),
            cred,
            new Capabilities(),
            new LifeTime(),
            new ArrayList<Extension>(),
            suite.serializeSignaturePrivateKey(sigKeyPair.getPrivate())
        );

        KeyPackage kp = new KeyPackage(
            suite,
            suite.getHPKE().serializePublicKey(initKeyPair.getPublic()),
            leafNode,
            new ArrayList<Extension>(),
            suite.serializeSignaturePrivateKey(sigKeyPair.getPrivate())
        );
        return new KeyPackageWithSecrets(initKeyPair, encryptionKeyPair, sigKeyPair, kp);
    }

    private LeafIndex findMember(TreeKEMPublicKey tree, byte[] id)
        throws Exception
    {
        //find member
        LeafNode leaf;
        LeafIndex index;
        for (int i = 0; i < tree.getSize().leafCount(); i++)
        {
            index = new LeafIndex(i);
            leaf = tree.getLeafNode(index);
            if (leaf == null)
            {
                continue;
            }
            if (Arrays.equals(leaf.getCredential().getIdentity(), id))
            {
                return index;
            }
        }
        throw new Exception("Unknown member identity");
    }

    private Proposal proposalFromDescription(MlsCipherSuite suite, byte[] groupID, TreeKEMPublicKey tree, MlsClient.ProposalDescription desc)
        throws Exception
    {
        SecureRandom random = new SecureRandom();
        switch (desc.getProposalType().toStringUtf8())
        {
        case "add":
            MLSMessage kp = (MLSMessage)MLSInputStream.decode(desc.getKeyPackage().toByteArray(), MLSMessage.class);
            return Proposal.add(kp.keyPackage);

        case "remove":
            LeafIndex removedIndex = findMember(tree, desc.getRemovedId().toByteArray());
            return Proposal.remove(removedIndex);

        case "externalPSK":
            byte[] externalPskID = desc.getPskId().toByteArray();
            byte[] extNonce = new byte[suite.getKDF().getHashLength()];
            random.nextBytes(extNonce);
            PreSharedKeyID extPskID = PreSharedKeyID.external(externalPskID, extNonce);
            return Proposal.preSharedKey(extPskID);

        case "resumptionPSK":
            long epoch = desc.getEpochId();
            byte[] resNonce = new byte[suite.getKDF().getHashLength()];
            PreSharedKeyID resPskID = PreSharedKeyID.resumption(ResumptionPSKUsage.APPLICATION, groupID, epoch, resNonce);
            return Proposal.preSharedKey(resPskID);

        case "groupContextExtensions":
        case "reinit":
            List<Extension> extList = new ArrayList<Extension>();
            for (int i = 0; i < desc.getExtensionsCount(); i++)
            {
                Extension ext = new Extension(desc.getExtensions(i).getExtensionType(), desc.getExtensions(i).getExtensionData().toByteArray());
                extList.add(ext);
            }

            if (desc.getProposalType().toStringUtf8().equals("reinit"))
            {
                return Proposal.reInit(
                    desc.getGroupId().toByteArray(),
                    ProtocolVersion.mls10,
                    MlsCipherSuite.getSuite((short)desc.getCipherSuite()),
                    extList
                );
            }
            // groupContextExtensions
            return Proposal.groupContextExtensions(extList);

        default:
            throw new IllegalStateException("Unknown proposal-by-value type: " + desc.getProposalType().toString());
        }
    }

    private void removeGroup(int stateID)
    {
        groupCache.remove(stateID);
    }

    /**
     * <pre>
     * The human-readable name of the stack
     * </pre>
     *
     * @param request
     * @param responseObserver
     */
    private void nameImpl(MlsClient.NameRequest request, StreamObserver<MlsClient.NameResponse> responseObserver)
    {

        MlsClient.NameResponse response = MlsClient.NameResponse.newBuilder()
            .setName("BouncyCastle")
            .build();

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void name(MlsClient.NameRequest request, StreamObserver<MlsClient.NameResponse> responseObserver)
    {
        catchWrap(new Function()
        {
            @Override
            public void run()
                throws Exception
            {
                nameImpl(request, responseObserver);
            }
        }, responseObserver);
    }

    /**
     * <pre>
     * List of supported ciphersuites
     * </pre>
     *
     * @param request
     * @param responseObserver
     */
    private void supportedCiphersuitesImpl(MlsClient.SupportedCiphersuitesRequest request, StreamObserver<MlsClient.SupportedCiphersuitesResponse> responseObserver)
    {
        MlsClient.SupportedCiphersuitesResponse.Builder builder = MlsClient.SupportedCiphersuitesResponse.newBuilder()
            .clearCiphersuites();

        for (short id : ALL_SUPPORTED_SUITES)
        {
            builder.addCiphersuites(id);
        }

        MlsClient.SupportedCiphersuitesResponse response = builder.build();
        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void supportedCiphersuites(MlsClient.SupportedCiphersuitesRequest request, StreamObserver<MlsClient.SupportedCiphersuitesResponse> responseObserver)
    {
        catchWrap(new Function()
        {
            @Override
            public void run()
                throws Exception
            {
                supportedCiphersuitesImpl(request, responseObserver);
            }
        }, responseObserver);
    }

    /**
     * <pre>
     * Ways to become a member of a group
     * </pre>
     *
     * @param request
     * @param responseObserver
     */

    public void createGroupImpl(MlsClient.CreateGroupRequest request, StreamObserver<MlsClient.CreateGroupResponse> responseObserver)
        throws Exception
    {
        byte[] groupID = request.getGroupId().toByteArray();
        MlsCipherSuite suite = MlsCipherSuite.getSuite((short)request.getCipherSuite());
        byte[] identity = request.getIdentity().toByteArray();

        AsymmetricCipherKeyPair leafKeyPair = suite.getHPKE().generatePrivateKey();
        AsymmetricCipherKeyPair sigKeyPair = suite.generateSignatureKeyPair();
        Credential cred = Credential.forBasic(identity);

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
        Group group = new Group(
            groupID,
            suite,
            leafKeyPair,
            suite.serializeSignaturePrivateKey(sigKeyPair.getPrivate()),
            leafNode.copy(leafNode.getEncryptionKey()),
            new ArrayList<Extension>()
        );

        int stateId = storeGroup(group, request.getEncryptHandshake());

        MlsClient.CreateGroupResponse response = MlsClient.CreateGroupResponse.newBuilder()
            .setStateId(stateId)
            .build();

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void createGroup(MlsClient.CreateGroupRequest request, StreamObserver<MlsClient.CreateGroupResponse> responseObserver)
    {
        catchWrap(new Function()
        {
            @Override
            public void run()
                throws Exception
            {
                createGroupImpl(request, responseObserver);
            }
        }, responseObserver);
    }

    /**
     * @param request
     * @param responseObserver
     */
    private void createKeyPackageImpl(MlsClient.CreateKeyPackageRequest request, StreamObserver<MlsClient.CreateKeyPackageResponse> responseObserver)
        throws Exception
    {
        MlsCipherSuite suite = MlsCipherSuite.getSuite((short)request.getCipherSuite());
        byte[] identity = request.getIdentity().toByteArray();

        KeyPackageWithSecrets kpSecrets = newKeyPackage(suite, identity);

        int joinID = storeJoin(kpSecrets);

        MlsClient.CreateKeyPackageResponse response = MlsClient.CreateKeyPackageResponse.newBuilder()
            .setInitPriv(ByteString.copyFrom(suite.getHPKE().serializePrivateKey(kpSecrets.initKeyPair.getPrivate())))
            .setEncryptionPriv(ByteString.copyFrom(suite.getHPKE().serializePrivateKey(kpSecrets.encryptionKeyPair.getPrivate())))
            .setSignaturePriv(ByteString.copyFrom(suite.serializeSignaturePrivateKey(kpSecrets.signatureKeyPair.getPrivate())))
            .setKeyPackage(ByteString.copyFrom(MLSOutputStream.encode(MLSMessage.keyPackage(kpSecrets.keyPackage))))
            .setTransactionId(joinID)
            .build();

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void createKeyPackage(MlsClient.CreateKeyPackageRequest request, StreamObserver<MlsClient.CreateKeyPackageResponse> responseObserver)
    {
        catchWrap(new Function()
        {
            @Override
            public void run()
                throws Exception
            {
                createKeyPackageImpl(request, responseObserver);
            }
        }, responseObserver);
    }

    /**
     * @param request
     * @param responseObserver
     */
    private void joinGroupImpl(MlsClient.JoinGroupRequest request, StreamObserver<MlsClient.JoinGroupResponse> responseObserver)
        throws Exception
    {
        CachedJoin join = loadJoin(request.getTransactionId());
        if (join == null)
        {
            throw new Exception("Unknown transaction ID");
        }

        MLSMessage welcomeMsg = (MLSMessage)MLSInputStream.decode(request.getWelcome().toByteArray(), MLSMessage.class);
        Welcome welcome = welcomeMsg.welcome;

        byte[] ratchetTreeBytes = request.getRatchetTree().toByteArray();

        TreeKEMPublicKey ratchetTree = null;
        if (ratchetTreeBytes.length > 0)
        {
            ratchetTree = (TreeKEMPublicKey)MLSInputStream.decode(ratchetTreeBytes, TreeKEMPublicKey.class);
            ratchetTree.setSuite(welcomeMsg.getCipherSuite());
        }

        MlsCipherSuite suite = welcome.getSuite();
        Group group = new Group(
            suite.getHPKE().serializePrivateKey(join.kpSecrets.initKeyPair.getPrivate()),
            join.kpSecrets.encryptionKeyPair,
            suite.serializeSignaturePrivateKey(join.kpSecrets.signatureKeyPair.getPrivate()),
            join.kpSecrets.keyPackage,
            welcome,
            ratchetTree,
            join.externalPsks,
            new HashMap<Group.EpochRef, byte[]>()
        );
        byte[] epochAuthenticator = group.getEpochAuthenticator();
        int stateID = storeGroup(group, request.getEncryptHandshake());

        MlsClient.JoinGroupResponse response = MlsClient.JoinGroupResponse.newBuilder()
            .setStateId(stateID)
            .setEpochAuthenticator(ByteString.copyFrom(epochAuthenticator))
            .build();

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void joinGroup(MlsClient.JoinGroupRequest request, StreamObserver<MlsClient.JoinGroupResponse> responseObserver)
    {
        catchWrap(new Function()
        {
            @Override
            public void run()
                throws Exception
            {
                joinGroupImpl(request, responseObserver);
            }
        }, responseObserver);
    }

    /**
     * @param request
     * @param responseObserver
     */
    private void externalJoinImpl(MlsClient.ExternalJoinRequest request, StreamObserver<MlsClient.ExternalJoinResponse> responseObserver)
        throws Exception
    {

        MLSMessage groupInfoMsg = (MLSMessage)MLSInputStream.decode(request.getGroupInfo().toByteArray(), MLSMessage.class);
        GroupInfo groupInfo = groupInfoMsg.groupInfo;
        MlsCipherSuite suite = groupInfo.getSuite();

        AsymmetricCipherKeyPair initKeyPair = suite.getHPKE().generatePrivateKey();
        AsymmetricCipherKeyPair leafKeyPair = suite.getHPKE().generatePrivateKey();
        AsymmetricCipherKeyPair sigKeyPair = suite.generateSignatureKeyPair();
        byte[] identity = request.getIdentity().toByteArray();
        Credential cred = Credential.forBasic(identity);

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

        KeyPackage kp = new KeyPackage(
            suite,
            suite.getHPKE().serializePublicKey(initKeyPair.getPublic()),
            leafNode,
            new ArrayList<Extension>(),
            suite.serializeSignaturePrivateKey(sigKeyPair.getPrivate())
        );

        byte[] ratchetTreeBytes = request.getRatchetTree().toByteArray();
        TreeKEMPublicKey ratchetTree = null;
        if (ratchetTreeBytes.length > 0)
        {
            ratchetTree = (TreeKEMPublicKey)MLSInputStream.decode(ratchetTreeBytes, TreeKEMPublicKey.class);
            ratchetTree.setSuite(suite);
        }

        LeafIndex removeIndex = null;
        boolean removePrior = request.getRemovePrior();
        if (removePrior)
        {
            // same as importTree()
            TreeKEMPublicKey outTree = null;
            for (Extension ext : groupInfo.getExtensions())
            {
                outTree = ext.getRatchetTree();
                if (outTree != null)
                {
                    break;
                }
            }
            if (ratchetTree != null)
            {
                outTree = TreeKEMPublicKey.clone(ratchetTree);
            }
            else if (outTree == null)
            {
                throw new Exception("No tree available");
            }

            // Scan through to find a matching identity
            for (int i = 0; i < outTree.getSize().leafCount(); i++)
            {
                LeafIndex index = new LeafIndex(i);
                LeafNode leaf = outTree.getLeafNode(index);
                if (leaf == null)
                {
                    continue;
                }

                if (!Arrays.equals(identity, leaf.getCredential().getIdentity()))
                {
                    continue;
                }
                removeIndex = index;
            }
            if (removeIndex == null)
            {
                throw new Exception("Prior appearance not found");
            }
        }
        // Install PSKs
        Map<Secret, byte[]> externalPSKs = new HashMap<Secret, byte[]>();
        for (int i = 0; i < request.getPsksCount(); i++)
        {
            MlsClient.PreSharedKey psk = request.getPsks(i);
            Secret pskID = new Secret(psk.getPskId().toByteArray());
            byte[] pskSecret = psk.getPskSecret().toByteArray();
            externalPSKs.put(pskID, pskSecret);
        }

        byte[] leafSecret = new byte[suite.getKDF().getHashLength()];
        SecureRandom random = new SecureRandom();
        random.nextBytes(leafSecret);

        Group.GroupWithMessage gwm = Group.externalJoin(
            new Secret(leafSecret),
            sigKeyPair,
            kp,
            groupInfo,
            ratchetTree,
            new Group.MessageOptions(false, new byte[0], 0),// encrypt should be false for external join!
            removeIndex,
            externalPSKs
        );

        int stateID = storeGroup(gwm.group, false);
        MlsClient.ExternalJoinResponse response = MlsClient.ExternalJoinResponse.newBuilder()
            .setStateId(stateID)
            .setCommit(ByteString.copyFrom(MLSOutputStream.encode(gwm.message)))
            .setEpochAuthenticator(ByteString.copyFrom(gwm.group.getEpochAuthenticator()))
            .build();

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void externalJoin(MlsClient.ExternalJoinRequest request, StreamObserver<MlsClient.ExternalJoinResponse> responseObserver)
    {
        catchWrap(new Function()
        {
            @Override
            public void run()
                throws Exception
            {
                externalJoinImpl(request, responseObserver);
            }
        }, responseObserver);
    }

    /**
     * <pre>
     * Operations using a group state
     * </pre>
     *
     * @param request
     * @param responseObserver
     */
    private void groupInfoImpl(CachedGroup entry, MlsClient.GroupInfoRequest request, StreamObserver<MlsClient.GroupInfoResponse> responseObserver)
        throws Exception
    {
        boolean inlineTree = !request.getExternalTree();
        MLSMessage groupInfo = entry.group.getGroupInfo(inlineTree);
        MlsClient.GroupInfoResponse.Builder builder = MlsClient.GroupInfoResponse.newBuilder()
            .setGroupInfo(ByteString.copyFrom(MLSOutputStream.encode(groupInfo)));
        if (!inlineTree)
        {
            builder.setRatchetTree(ByteString.copyFrom(MLSOutputStream.encode(entry.group.getTree())));
        }

        MlsClient.GroupInfoResponse response = builder.build();
        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void groupInfo(MlsClient.GroupInfoRequest request, StreamObserver<MlsClient.GroupInfoResponse> responseObserver)
    {
        stateWrap(new FunctionWithState()
        {
            @Override
            public void run(CachedGroup group)
                throws Exception
            {
                groupInfoImpl(group, request, responseObserver);
            }
        }, request, responseObserver);

    }

    /**
     * @param request
     * @param responseObserver
     */
    private void stateAuthImpl(CachedGroup entry, MlsClient.StateAuthRequest request, StreamObserver<MlsClient.StateAuthResponse> responseObserver)
    {
        MlsClient.StateAuthResponse response = MlsClient.StateAuthResponse.newBuilder()
            .setStateAuthSecret(ByteString.copyFrom(entry.group.getEpochAuthenticator()))
            .build();

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void stateAuth(MlsClient.StateAuthRequest request, StreamObserver<MlsClient.StateAuthResponse> responseObserver)
    {
        stateWrap(new FunctionWithState()
        {
            @Override
            public void run(CachedGroup group)
                throws Exception
            {
                stateAuthImpl(group, request, responseObserver);
            }
        }, request, responseObserver);
    }

    /**
     * @param request
     * @param responseObserver
     */
    private void exportImpl(CachedGroup entry, MlsClient.ExportRequest request, StreamObserver<MlsClient.ExportResponse> responseObserver)
        throws IOException
    {
        String label = request.getLabel();
        byte[] context = request.getContext().toByteArray();
        int size = request.getKeyLength();
        byte[] secret = entry.group.getKeySchedule().MLSExporter(label, context, size);
        MlsClient.ExportResponse response = MlsClient.ExportResponse.newBuilder()
            .setExportedSecret(ByteString.copyFrom(secret))
            .build();

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void export(MlsClient.ExportRequest request, StreamObserver<MlsClient.ExportResponse> responseObserver)
    {
        stateWrap(new FunctionWithState()
        {
            @Override
            public void run(CachedGroup group)
                throws Exception
            {
                exportImpl(group, request, responseObserver);
            }
        }, request, responseObserver);
    }

    /**
     * @param request
     * @param responseObserver
     */
    private void protectImpl(CachedGroup entry, MlsClient.ProtectRequest request, StreamObserver<MlsClient.ProtectResponse> responseObserver)
        throws Exception
    {
        MLSMessage ct = entry.group.protect(
            request.getAuthenticatedData().toByteArray(),
            request.getPlaintext().toByteArray(),
            0
        );
        MlsClient.ProtectResponse response = MlsClient.ProtectResponse.newBuilder()
            .setCiphertext(ByteString.copyFrom(MLSOutputStream.encode(ct)))
            .build();

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void protect(MlsClient.ProtectRequest request, StreamObserver<MlsClient.ProtectResponse> responseObserver)
    {
        stateWrap(new FunctionWithState()
        {
            @Override
            public void run(CachedGroup group)
                throws Exception
            {
                protectImpl(group, request, responseObserver);
            }
        }, request, responseObserver);
    }

    /**
     * @param request
     * @param responseObserver
     */
    private void unprotectImpl(CachedGroup entry, MlsClient.UnprotectRequest request, StreamObserver<MlsClient.UnprotectResponse> responseObserver)
        throws Exception
    {
        MLSMessage ct = (MLSMessage)MLSInputStream.decode(request.getCiphertext().toByteArray(), MLSMessage.class);

        // Locate the right epoch to decrypt with
        byte[] groupID = entry.group.getGroupID();
        long epoch = ct.getEpoch();
        Group group = entry.group;
        if (entry.group.getEpoch() != epoch)
        {
            CachedGroup cached = findState(groupID, epoch);
            if (cached == null)
            {
                throw new Exception("Unknown state for unprotect");
            }
            group = cached.group;
        }

        // Decrypt the message
        byte[][] authAndPt = group.unprotect(ct);
        byte[] aad = authAndPt[0];
        byte[] pt = authAndPt[1];

        MlsClient.UnprotectResponse response = MlsClient.UnprotectResponse.newBuilder()
            .setAuthenticatedData(ByteString.copyFrom(aad))
            .setPlaintext(ByteString.copyFrom(pt))
            .build();

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void unprotect(MlsClient.UnprotectRequest request, StreamObserver<MlsClient.UnprotectResponse> responseObserver)
    {
        stateWrap(new FunctionWithState()
        {
            @Override
            public void run(CachedGroup group)
                throws Exception
            {
                unprotectImpl(group, request, responseObserver);
            }
        }, request, responseObserver);
    }

    /**
     * @param request
     * @param responseObserver
     */
    private void storePSKImpl(MlsClient.StorePSKRequest request, StreamObserver<MlsClient.StorePSKResponse> responseObserver)
        throws StatusException
    {
        MlsClient.StorePSKResponse response = MlsClient.StorePSKResponse.newBuilder().build();
        int id = request.getStateOrTransactionId();
        Secret pskId = new Secret(request.getPskId().toByteArray());
        byte[] pskSecret = request.getPskSecret().toByteArray();

        CachedJoin join = loadJoin(id);
        if (join != null)
        {
            join.externalPsks.put(pskId, pskSecret);
            responseObserver.onNext(response);
            responseObserver.onCompleted();
            return;
        }

        CachedGroup cached = loadGroup(id);
        if (cached == null)
        {
            throw Status.NOT_FOUND.withDescription("Unknown state").asException();
        }

        cached.group.insertExternalPsk(pskId, pskSecret);

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void storePSK(MlsClient.StorePSKRequest request, StreamObserver<MlsClient.StorePSKResponse> responseObserver)
    {
        catchWrap(new Function()
        {
            @Override
            public void run()
                throws Exception
            {
                storePSKImpl(request, responseObserver);
            }
        }, responseObserver);
    }

    /**
     * @param request
     * @param responseObserver
     */
    private void addProposalImpl(CachedGroup entry, MlsClient.AddProposalRequest request, StreamObserver<MlsClient.ProposalResponse> responseObserver)
        throws Exception
    {
        MLSMessage keyPackage = (MLSMessage)MLSInputStream.decode(request.getKeyPackage().toByteArray(), MLSMessage.class);
        MLSMessage message = entry.group.add(keyPackage.keyPackage, entry.messageOptions);

        MlsClient.ProposalResponse response = MlsClient.ProposalResponse.newBuilder()
            .setProposal(ByteString.copyFrom(MLSOutputStream.encode(message)))
            .build();

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void addProposal(MlsClient.AddProposalRequest request, StreamObserver<MlsClient.ProposalResponse> responseObserver)
    {
        stateWrap(new FunctionWithState()
        {
            @Override
            public void run(CachedGroup group)
                throws Exception
            {
                addProposalImpl(group, request, responseObserver);
            }
        }, request, responseObserver);
    }

    /**
     * @param request
     * @param responseObserver
     */
    private void updateProposalImpl(CachedGroup entry, MlsClient.UpdateProposalRequest request, StreamObserver<MlsClient.ProposalResponse> responseObserver)
        throws Exception
    {
        AsymmetricCipherKeyPair leafSk = entry.group.getSuite().getHPKE().generatePrivateKey();
        Proposal update = entry.group.updateProposal(leafSk, new Group.LeafNodeOptions());
        MLSMessage message = entry.group.update(update, entry.messageOptions);

        MlsClient.ProposalResponse response = MlsClient.ProposalResponse.newBuilder()
            .setProposal(ByteString.copyFrom(MLSOutputStream.encode(message)))
            .build();

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void updateProposal(MlsClient.UpdateProposalRequest request, StreamObserver<MlsClient.ProposalResponse> responseObserver)
    {
        stateWrap(new FunctionWithState()
        {
            @Override
            public void run(CachedGroup group)
                throws Exception
            {
                updateProposalImpl(group, request, responseObserver);
            }
        }, request, responseObserver);
    }

    /**
     * @param request
     * @param responseObserver
     */
    private void removeProposalImpl(CachedGroup entry, MlsClient.RemoveProposalRequest request, StreamObserver<MlsClient.ProposalResponse> responseObserver)
        throws Exception
    {
        LeafIndex removedIndex = findMember(entry.group.getTree(), request.getRemovedId().toByteArray());
        MLSMessage message = entry.group.remove(removedIndex, entry.messageOptions);

        MlsClient.ProposalResponse response = MlsClient.ProposalResponse.newBuilder()
            .setProposal(ByteString.copyFrom(MLSOutputStream.encode(message)))
            .build();

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void removeProposal(MlsClient.RemoveProposalRequest request, StreamObserver<MlsClient.ProposalResponse> responseObserver)
    {
        stateWrap(new FunctionWithState()
        {
            @Override
            public void run(CachedGroup group)
                throws Exception
            {
                removeProposalImpl(group, request, responseObserver);
            }
        }, request, responseObserver);
    }

    /**
     * @param request
     * @param responseObserver
     */
    private void externalPSKProposalImpl(CachedGroup entry, MlsClient.ExternalPSKProposalRequest request, StreamObserver<MlsClient.ProposalResponse> responseObserver)
        throws Exception
    {
        byte[] pskID = request.getPskId().toByteArray();
        MLSMessage message = entry.group.preSharedKey(pskID, entry.messageOptions);

        MlsClient.ProposalResponse response = MlsClient.ProposalResponse.newBuilder()
            .setProposal(ByteString.copyFrom(MLSOutputStream.encode(message)))
            .build();

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void externalPSKProposal(MlsClient.ExternalPSKProposalRequest request, StreamObserver<MlsClient.ProposalResponse> responseObserver)
    {
        stateWrap(new FunctionWithState()
        {
            @Override
            public void run(CachedGroup group)
                throws Exception
            {
                externalPSKProposalImpl(group, request, responseObserver);
            }
        }, request, responseObserver);
    }

    /**
     * @param request
     * @param responseObserver
     */
    private void resumptionPSKProposalImpl(CachedGroup entry, MlsClient.ResumptionPSKProposalRequest request, StreamObserver<MlsClient.ProposalResponse> responseObserver)
        throws Exception
    {
        MLSMessage message = entry.group.preSharedKey(entry.group.getGroupID(), request.getEpochId(), entry.messageOptions);

        MlsClient.ProposalResponse response = MlsClient.ProposalResponse.newBuilder()
            .setProposal(ByteString.copyFrom(MLSOutputStream.encode(message)))
            .build();

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void resumptionPSKProposal(MlsClient.ResumptionPSKProposalRequest request, StreamObserver<MlsClient.ProposalResponse> responseObserver)
    {
        stateWrap(new FunctionWithState()
        {
            @Override
            public void run(CachedGroup group)
                throws Exception
            {
                resumptionPSKProposalImpl(group, request, responseObserver);
            }
        }, request, responseObserver);
    }

    /**
     * @param request
     * @param responseObserver
     */
    private void groupContextExtensionsProposalImpl(CachedGroup entry, MlsClient.GroupContextExtensionsProposalRequest request, StreamObserver<MlsClient.ProposalResponse> responseObserver)
        throws Exception
    {
        List<Extension> extList = new ArrayList<Extension>();
        for (int i = 0; i < request.getExtensionsCount(); i++)
        {
            Extension ext = new Extension(request.getExtensions(i).getExtensionType(), request.getExtensions(i).getExtensionData().toByteArray());
            extList.add(ext);
        }

        MLSMessage message = entry.group.groupContextExtensions(extList, entry.messageOptions);

        MlsClient.ProposalResponse response = MlsClient.ProposalResponse.newBuilder()
            .setProposal(ByteString.copyFrom(MLSOutputStream.encode(message)))
            .build();

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void groupContextExtensionsProposal(MlsClient.GroupContextExtensionsProposalRequest request, StreamObserver<MlsClient.ProposalResponse> responseObserver)
    {
        stateWrap(new FunctionWithState()
        {
            @Override
            public void run(CachedGroup group)
                throws Exception
            {
                groupContextExtensionsProposalImpl(group, request, responseObserver);
            }
        }, request, responseObserver);
    }

    /**
     * @param request
     * @param responseObserver
     */
    private void commitImpl(CachedGroup entry, MlsClient.CommitRequest request, StreamObserver<MlsClient.CommitResponse> responseObserver)
        throws Exception
    {
        int byRefSize = request.getByReferenceCount();
        for (int i = 0; i < byRefSize; i++)
        {
            byte[] msg = request.getByReference(i).toByteArray();
            Group shouldBeNull = entry.group.handle(msg, null);
            if (shouldBeNull != null)
            {
                throw new Exception("Commit included among proposals");
            }
        }

        // create by value proposals
        List<Proposal> byValue = new ArrayList<Proposal>();
        for (int i = 0; i < request.getByValueCount(); i++)
        {
            MlsClient.ProposalDescription desc = request.getByValue(i);
            Proposal proposal = proposalFromDescription(
                entry.group.getSuite(),
                entry.group.getGroupID(),
                entry.group.getTree(),
                desc
            );
            byValue.add(proposal);
        }

        boolean forcePath = request.getForcePath();
        boolean inlineTree = !request.getExternalTree();

        SecureRandom random = new SecureRandom();
        byte[] leafSecret = new byte[entry.group.getSuite().getKDF().getHashLength()];
        random.nextBytes(leafSecret);
        Group.GroupWithMessage gwm = entry.group.commit(
            new Secret(leafSecret),
            new Group.CommitOptions(byValue, inlineTree, forcePath, null),
            entry.messageOptions,
            new Group.CommitParameters(NORMAL_COMMIT_PARAMS)
        );
        byte[] commitBytes = MLSOutputStream.encode(gwm.message);
        gwm.message.wireFormat = WireFormat.mls_welcome;
        byte[] welcomeBytes = MLSOutputStream.encode(gwm.message);

        int nextID = storeGroup(gwm.group, entry.encryptHandshake);

        entry.pendingCommit = commitBytes;
        entry.pendingGroupID = nextID;

        MlsClient.CommitResponse.Builder builder = MlsClient.CommitResponse.newBuilder()
            .setCommit(ByteString.copyFrom(commitBytes))
            .setWelcome(ByteString.copyFrom(welcomeBytes));

        if (!inlineTree)
        {
            builder.setRatchetTree(ByteString.copyFrom(MLSOutputStream.encode(gwm.group.getTree())));
        }

        responseObserver.onNext(builder.build());
        responseObserver.onCompleted();
    }

    @Override
    public void commit(MlsClient.CommitRequest request, StreamObserver<MlsClient.CommitResponse> responseObserver)
    {
        stateWrap(new FunctionWithState()
        {
            @Override
            public void run(CachedGroup group)
                throws Exception
            {
                commitImpl(group, request, responseObserver);
            }
        }, request, responseObserver);
    }

    /**
     * @param request
     * @param responseObserver
     */
    private void handleCommitImpl(CachedGroup entry, MlsClient.HandleCommitRequest request, StreamObserver<MlsClient.HandleCommitResponse> responseObserver)
        throws Exception
    {
        // Handle our own commits with caching
        byte[] commitBytes = request.getCommit().toByteArray();
        if (entry.pendingCommit != null && Arrays.equals(commitBytes, entry.pendingCommit))
        {
            MlsClient.HandleCommitResponse response = MlsClient.HandleCommitResponse.newBuilder()
                .setStateId(entry.pendingGroupID)
                .build();
            entry.resetPending();

            responseObserver.onNext(response);
            responseObserver.onCompleted();
            return;
        }
        else if (entry.pendingGroupID != -1)
        {
            removeGroup(entry.pendingGroupID);
            entry.resetPending();
        }

        int proposalSize = request.getProposalCount();
        for (int i = 0; i < proposalSize; i++)
        {
            byte[] messageBytes = request.getProposal(i).toByteArray();
            Group shouldBeNull = entry.group.handle(messageBytes, null);
            if (shouldBeNull != null)
            {
                throw new Exception("Commit included among proposals");
            }
        }

        Group next = entry.group.handle(commitBytes, null);
        if (next == null)
        {
            throw new Exception("Commit failed to produce a new state");
        }

        byte[] epochAuthenticator = next.getEpochAuthenticator();
        int nextID = storeGroup(next, entry.encryptHandshake);

        MlsClient.HandleCommitResponse response = MlsClient.HandleCommitResponse.newBuilder()
            .setStateId(nextID)
            .setEpochAuthenticator(ByteString.copyFrom(epochAuthenticator))
            .build();

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void handleCommit(MlsClient.HandleCommitRequest request, StreamObserver<MlsClient.HandleCommitResponse> responseObserver)
    {
        stateWrap(new FunctionWithState()
        {
            @Override
            public void run(CachedGroup group)
                throws Exception
            {
                handleCommitImpl(group, request, responseObserver);
            }
        }, request, responseObserver);
    }

    /**
     * @param request
     * @param responseObserver
     */
    private void handlePendingCommitImpl(CachedGroup entry, MlsClient.HandlePendingCommitRequest request, StreamObserver<MlsClient.HandleCommitResponse> responseObserver)
        throws Exception
    {
        if (entry.pendingCommit == null || entry.pendingGroupID == -1)
        {
            throw new Exception("No pending commit to handle");
        }

        int nextID = entry.pendingGroupID;
        CachedGroup next = loadGroup(nextID);
        if (next == null)
        {
            throw new Exception("No Internal error: No state for next ID");
        }

        byte[] epochAuthenticator = next.group.getEpochAuthenticator();
        MlsClient.HandleCommitResponse response = MlsClient.HandleCommitResponse.newBuilder()
            .setStateId(nextID)
            .setEpochAuthenticator(ByteString.copyFrom(epochAuthenticator))
            .build();

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void handlePendingCommit(MlsClient.HandlePendingCommitRequest request, StreamObserver<MlsClient.HandleCommitResponse> responseObserver)
    {
        stateWrap(new FunctionWithState()
        {
            @Override
            public void run(CachedGroup group)
                throws Exception
            {
                handlePendingCommitImpl(group, request, responseObserver);
            }
        }, request, responseObserver);
    }

    /**
     * <pre>
     * Reinitialization
     * </pre>
     *
     * @param request
     * @param responseObserver
     */
    private void reInitProposalImpl(CachedGroup entry, MlsClient.ReInitProposalRequest request, StreamObserver<MlsClient.ProposalResponse> responseObserver)
        throws Exception
    {
        byte[] groupID = request.getGroupId().toByteArray();
        ProtocolVersion version = ProtocolVersion.mls10;
        MlsCipherSuite suite = MlsCipherSuite.getSuite((short)request.getCipherSuite());

        List<Extension> extList = new ArrayList<Extension>();
        for (int i = 0; i < request.getExtensionsCount(); i++)
        {
            Extension ext = new Extension(request.getExtensions(i).getExtensionType(), request.getExtensions(i).getExtensionData().toByteArray());
            extList.add(ext);
        }

        MLSMessage message = entry.group.reinit(groupID, version, suite, extList, entry.messageOptions);
        MlsClient.ProposalResponse response = MlsClient.ProposalResponse.newBuilder()
            .setProposal(ByteString.copyFrom(MLSOutputStream.encode(message)))
            .build();

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void reInitProposal(MlsClient.ReInitProposalRequest request, StreamObserver<MlsClient.ProposalResponse> responseObserver)
    {
        stateWrap(new FunctionWithState()
        {
            @Override
            public void run(CachedGroup group)
                throws Exception
            {
                reInitProposalImpl(group, request, responseObserver);
            }
        }, request, responseObserver);
    }

    /**
     * @param request
     * @param responseObserver
     */
    private void reInitCommitImpl(CachedGroup entry, MlsClient.CommitRequest request, StreamObserver<MlsClient.CommitResponse> responseObserver)
        throws Exception
    {
        boolean inlineTree = !request.getExternalTree();
        boolean forcePath = request.getForcePath();

        // For now ReInit proposal must be provided by reference
        if (request.getByReferenceCount() != 1)
        {
            throw new Exception("Malformed ReInit CommitRequest");
        }
        byte[] reinitProposal = request.getByReference(0).toByteArray();
        Group shouldBeNull = entry.group.handle(reinitProposal, null);
        if (shouldBeNull != null)
        {
            throw new Exception("Commit included among proposals");
        }

        SecureRandom random = new SecureRandom();
        byte[] leafSecret = new byte[entry.group.getSuite().getKDF().getHashLength()];
        random.nextBytes(leafSecret);
        Group.CommitOptions commitOptions = new Group.CommitOptions(new ArrayList<Proposal>(), inlineTree, forcePath, null);
        Group.TombstoneWithMessage twm = entry.group.reinitCommit(leafSecret, commitOptions, entry.messageOptions);

        // cache the reinit
        LeafNode leaf = entry.group.getTree().getLeafNode(entry.group.getIndex());
        byte[] identity = leaf.getCredential().getIdentity();
        KeyPackageWithSecrets kpSk = newKeyPackage(twm.getSuite(), identity);
        ;
        int reinitID = storeReinit(kpSk, twm, entry.encryptHandshake);
        byte[] commitBytes = MLSOutputStream.encode(twm.getMessage());

        MlsClient.CommitResponse response = MlsClient.CommitResponse.newBuilder()
            .setCommit(ByteString.copyFrom(commitBytes))
            .build();

        entry.pendingCommit = commitBytes;
        entry.pendingGroupID = reinitID;

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void reInitCommit(MlsClient.CommitRequest request, StreamObserver<MlsClient.CommitResponse> responseObserver)
    {
        stateWrap(new FunctionWithState()
        {
            @Override
            public void run(CachedGroup group)
                throws Exception
            {
                reInitCommitImpl(group, request, responseObserver);
            }
        }, request, responseObserver);
    }

    /**
     * @param request
     * @param responseObserver
     */
    private void handlePendingReInitCommitImpl(CachedGroup entry, MlsClient.HandlePendingCommitRequest request, StreamObserver<MlsClient.HandleReInitCommitResponse> responseObserver)
        throws Exception
    {
        if (entry.pendingCommit == null || entry.pendingGroupID == -1)
        {
            throw new Exception("No pending commit to handle");
        }

        int reinitID = entry.pendingGroupID;

        CachedReinit reinit = loadReinit(reinitID);
        if (reinit == null)
        {
            throw new Exception("Internal error: No state for next ID");
        }

        MlsClient.HandleReInitCommitResponse response = MlsClient.HandleReInitCommitResponse.newBuilder()
            .setReinitId(reinitID)
            .setKeyPackage(ByteString.copyFrom(MLSOutputStream.encode(MLSMessage.keyPackage(reinit.kpSk.keyPackage))))
            .setEpochAuthenticator(ByteString.copyFrom(reinit.tombstone.getEpochAuthenticator()))
            .build();

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void handlePendingReInitCommit(MlsClient.HandlePendingCommitRequest request, StreamObserver<MlsClient.HandleReInitCommitResponse> responseObserver)
    {
        stateWrap(new FunctionWithState()
        {
            @Override
            public void run(CachedGroup group)
                throws Exception
            {
                handlePendingReInitCommitImpl(group, request, responseObserver);
            }
        }, request, responseObserver);
    }

    /**
     * @param request
     * @param responseObserver
     */
    private void handleReInitCommitImpl(CachedGroup entry, MlsClient.HandleCommitRequest request, StreamObserver<MlsClient.HandleReInitCommitResponse> responseObserver)
        throws Exception
    {
        //TODO: Reinit proposal must be provided by reference for now
        if (request.getProposalCount() != 1)
        {
            throw new Exception("Malformed ReInit CommitRequest");
        }
        byte[] reinitMessage = request.getProposal(0).toByteArray();
        Group shouldBeNull = entry.group.handle(reinitMessage, null);
        if (shouldBeNull != null)
        {
            throw new Exception("Commit included among proposals");
        }

        MLSMessage commit = (MLSMessage)MLSInputStream.decode(request.getCommit().toByteArray(), MLSMessage.class);
        Group.Tombstone tombstone = entry.group.handleReinitCommit(commit);

        // Cache the reinit
        LeafNode leafNode = entry.group.getTree().getLeafNode(entry.group.getIndex());
        byte[] identity = leafNode.getCredential().getIdentity();
        KeyPackageWithSecrets kpSk = newKeyPackage(tombstone.getSuite(), identity);

        int reinitID = storeReinit(kpSk, tombstone, entry.encryptHandshake);

        MlsClient.HandleReInitCommitResponse response = MlsClient.HandleReInitCommitResponse.newBuilder()
            .setReinitId(reinitID)
            .setKeyPackage(ByteString.copyFrom(MLSOutputStream.encode(MLSMessage.keyPackage(kpSk.keyPackage))))
            .setEpochAuthenticator(ByteString.copyFrom(tombstone.getEpochAuthenticator()))
            .build();

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void handleReInitCommit(MlsClient.HandleCommitRequest request, StreamObserver<MlsClient.HandleReInitCommitResponse> responseObserver)
    {
        stateWrap(new FunctionWithState()
        {
            @Override
            public void run(CachedGroup group)
                throws Exception
            {
                handleReInitCommitImpl(group, request, responseObserver);
            }
        }, request, responseObserver);
    }

    /**
     * @param request
     * @param responseObserver
     */
    private void reInitWelcomeImpl(MlsClient.ReInitWelcomeRequest request, StreamObserver<MlsClient.CreateSubgroupResponse> responseObserver)
        throws Exception
    {
        // Load the reinit
        CachedReinit reinit = loadReinit(request.getReinitId());
        if (reinit == null)
        {
            throw Status.INVALID_ARGUMENT.withDescription("Unknown reinit ID").asException();
        }

        // Import the KeyPackages
        List<KeyPackage> keyPackages = new ArrayList<KeyPackage>();
        for (int i = 0; i < request.getKeyPackageCount(); i++)
        {
            MLSMessage message = (MLSMessage)MLSInputStream.decode(request.getKeyPackage(i).toByteArray(), MLSMessage.class);
            keyPackages.add(message.keyPackage);
        }

        // Create the Welcome
        boolean inlineTree = !request.getExternalTree();
        boolean forcePath = request.getForcePath();
        MlsCipherSuite suite = reinit.tombstone.getSuite();
        byte[] leafSecret = new byte[suite.getKDF().getHashLength()];

        Group.GroupWithMessage gwm = reinit.tombstone.createWelcome(
            reinit.kpSk.encryptionKeyPair,
            suite.serializeSignaturePrivateKey(reinit.kpSk.signatureKeyPair.getPrivate()),
            reinit.kpSk.keyPackage.getLeafNode(),
            keyPackages,
            leafSecret,
            new Group.CommitOptions(null, inlineTree, forcePath, null)
        );
        byte[] welcomeData = MLSOutputStream.encode(gwm.message);

        // Store the resulting state
        int stateID = storeGroup(gwm.group, reinit.encryptHandshake);
        MlsClient.CreateSubgroupResponse.Builder builder = MlsClient.CreateSubgroupResponse.newBuilder()
            .setStateId(stateID)
            .setWelcome(ByteString.copyFrom(welcomeData))
            .setEpochAuthenticator(ByteString.copyFrom(gwm.group.getEpochAuthenticator()));

        if (!inlineTree)
        {
            builder.setRatchetTree(ByteString.copyFrom(MLSOutputStream.encode(gwm.group.getTree())));
        }

        responseObserver.onNext(builder.build());
        responseObserver.onCompleted();
    }

    @Override
    public void reInitWelcome(MlsClient.ReInitWelcomeRequest request, StreamObserver<MlsClient.CreateSubgroupResponse> responseObserver)
    {
        catchWrap(new Function()
        {
            @Override
            public void run()
                throws Exception
            {
                reInitWelcomeImpl(request, responseObserver);
            }
        }, responseObserver);
    }

    /**
     * @param request
     * @param responseObserver
     */
    private void handleReInitWelcomeImpl(MlsClient.HandleReInitWelcomeRequest request, StreamObserver<MlsClient.JoinGroupResponse> responseObserver)
        throws Exception
    {
        // Load the reinit
        CachedReinit reinit = loadReinit(request.getReinitId());
        if (reinit == null)
        {
            throw Status.INVALID_ARGUMENT.withDescription("Unknown reinit ID").asException();
        }

        // Process the welcome
        MLSMessage welcome = (MLSMessage)MLSInputStream.decode(request.getWelcome().toByteArray(), MLSMessage.class);

        byte[] ratchetTreeBytes = request.getRatchetTree().toByteArray();
        TreeKEMPublicKey ratchetTree = null;
        if (ratchetTreeBytes.length > 0)
        {
            ratchetTree = (TreeKEMPublicKey)MLSInputStream.decode(ratchetTreeBytes, TreeKEMPublicKey.class);
            ratchetTree.setSuite(welcome.getCipherSuite());
        }

        Group group = reinit.tombstone.handleWelcome(
            reinit.kpSk.initKeyPair,
            reinit.kpSk.encryptionKeyPair,
            reinit.kpSk.signatureKeyPair,
            reinit.kpSk.keyPackage,
            welcome,
            ratchetTree
        );

        // Store the resulting group
        int stateID = storeGroup(group, reinit.encryptHandshake);

        MlsClient.JoinGroupResponse response = MlsClient.JoinGroupResponse.newBuilder()
            .setStateId(stateID)
            .setEpochAuthenticator(ByteString.copyFrom(group.getEpochAuthenticator()))
            .build();

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void handleReInitWelcome(MlsClient.HandleReInitWelcomeRequest request, StreamObserver<MlsClient.JoinGroupResponse> responseObserver)
    {
        catchWrap(new Function()
        {
            @Override
            public void run()
                throws Exception
            {
                handleReInitWelcomeImpl(request, responseObserver);
            }
        }, responseObserver);
    }

    /**
     * <pre>
     * Subgroup Branching
     * </pre>
     *
     * @param request
     * @param responseObserver
     */
    private void createBranchImpl(CachedGroup entry, MlsClient.CreateBranchRequest request, StreamObserver<MlsClient.CreateSubgroupResponse> responseObserver)
        throws Exception
    {
        // Import KeyPackages
        List<KeyPackage> keyPackages = new ArrayList<KeyPackage>();
        for (int i = 0; i < request.getKeyPackagesCount(); i++)
        {
            MLSMessage message = (MLSMessage)MLSInputStream.decode(request.getKeyPackages(i).toByteArray(), MLSMessage.class);
            keyPackages.add(message.keyPackage);
        }

        // Import extensions
        List<Extension> extList = new ArrayList<Extension>();
        for (int i = 0; i < request.getExtensionsCount(); i++)
        {
            Extension ext = new Extension(request.getExtensions(i).getExtensionType(), request.getExtensions(i).getExtensionData().toByteArray());
            extList.add(ext);
        }

        // Create the branch
        LeafNode leaf = entry.group.getTree().getLeafNode(entry.group.getIndex());
        byte[] identity = leaf.getCredential().getIdentity();

        boolean inlineTree = !request.getExternalTree();
        boolean forcePath = request.getForcePath();
        byte[] groupID = request.getGroupId().toByteArray();
        MlsCipherSuite suite = entry.group.getSuite();
        KeyPackageWithSecrets kpSK = newKeyPackage(suite, identity);
        byte[] leafSecret = new byte[suite.getKDF().getHashLength()];
        SecureRandom random = new SecureRandom();
        random.nextBytes(leafSecret);

        Group.GroupWithMessage gwm = entry.group.createBranch(
            groupID,
            kpSK.encryptionKeyPair,
            kpSK.signatureKeyPair,
            kpSK.keyPackage.getLeafNode(),
            extList,
            keyPackages,
            leafSecret,
            new Group.CommitOptions(null, inlineTree, forcePath, null)
        );

        int nextID = storeGroup(gwm.group, entry.encryptHandshake);

        MlsClient.CreateSubgroupResponse.Builder builder = MlsClient.CreateSubgroupResponse.newBuilder()
            .setStateId(nextID)
            .setWelcome(ByteString.copyFrom(MLSOutputStream.encode(gwm.message)))
            .setEpochAuthenticator(ByteString.copyFrom(gwm.group.getEpochAuthenticator()));

        if (!inlineTree)
        {
            builder.setRatchetTree(ByteString.copyFrom(MLSOutputStream.encode(gwm.group.getTree())));
        }

        responseObserver.onNext(builder.build());
        responseObserver.onCompleted();
    }

    @Override
    public void createBranch(MlsClient.CreateBranchRequest request, StreamObserver<MlsClient.CreateSubgroupResponse> responseObserver)
    {
        stateWrap(new FunctionWithState()
        {
            @Override
            public void run(CachedGroup group)
                throws Exception
            {
                createBranchImpl(group, request, responseObserver);
            }
        }, request, responseObserver);
    }

    /**
     * @param request
     * @param responseObserver
     */
    private void handleBranchImpl(CachedGroup entry, MlsClient.HandleBranchRequest request, StreamObserver<MlsClient.HandleBranchResponse> responseObserver)
        throws Exception
    {
        CachedJoin join = loadJoin(request.getTransactionId());
        if (join == null)
        {
            throw Status.INVALID_ARGUMENT.withDescription("Unknown transaction ID").asException();
        }

        MLSMessage welcome = (MLSMessage)MLSInputStream.decode(request.getWelcome().toByteArray(), MLSMessage.class);
        byte[] ratchetTreeBytes = request.getRatchetTree().toByteArray();
        TreeKEMPublicKey ratchetTree = null;
        if (ratchetTreeBytes.length > 0)
        {
            ratchetTree = (TreeKEMPublicKey)MLSInputStream.decode(ratchetTreeBytes, TreeKEMPublicKey.class);
            ratchetTree.setSuite(welcome.getCipherSuite());
        }

        Group group = entry.group.handleBranch(
            join.kpSecrets.initKeyPair,
            join.kpSecrets.encryptionKeyPair,
            join.kpSecrets.signatureKeyPair,
            join.kpSecrets.keyPackage,
            welcome,
            ratchetTree
        );

        int stateID = storeGroup(group, entry.encryptHandshake);

        MlsClient.HandleBranchResponse response = MlsClient.HandleBranchResponse.newBuilder()
            .setStateId(stateID)
            .setEpochAuthenticator(ByteString.copyFrom(group.getEpochAuthenticator()))
            .build();

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void handleBranch(MlsClient.HandleBranchRequest request, StreamObserver<MlsClient.HandleBranchResponse> responseObserver)
    {
        stateWrap(new FunctionWithState()
        {
            @Override
            public void run(CachedGroup group)
                throws Exception
            {
                handleBranchImpl(group, request, responseObserver);
            }
        }, request, responseObserver);
    }

    /**
     * <pre>
     * External proposals
     * </pre>
     *
     * @param request
     * @param responseObserver
     */
    private void newMemberAddProposalImpl(MlsClient.NewMemberAddProposalRequest request, StreamObserver<MlsClient.NewMemberAddProposalResponse> responseObserver)
        throws Exception
    {
        MLSMessage groupInfoMsg = (MLSMessage)MLSInputStream.decode(request.getGroupInfo().toByteArray(), MLSMessage.class);
        GroupInfo groupInfo = groupInfoMsg.groupInfo;
        MlsCipherSuite suite = groupInfo.getSuite();

        KeyPackageWithSecrets kpSk = newKeyPackage(suite, request.getIdentity().toByteArray());

        byte[] initSk = suite.getHPKE().serializePrivateKey(kpSk.initKeyPair.getPrivate());
        byte[] encryptionSk = suite.getHPKE().serializePrivateKey(kpSk.encryptionKeyPair.getPrivate());
        byte[] signatureSk = suite.serializeSignaturePrivateKey(kpSk.signatureKeyPair.getPrivate());

        MLSMessage proposal = Group.newMemberAdd(
            groupInfo.getGroupID(),
            groupInfo.getEpoch(),
            kpSk.keyPackage,
            kpSk.signatureKeyPair
        );

        int joinID = storeJoin(kpSk);

        MlsClient.NewMemberAddProposalResponse response = MlsClient.NewMemberAddProposalResponse.newBuilder()
            .setInitPriv(ByteString.copyFrom(initSk))
            .setEncryptionPriv(ByteString.copyFrom(encryptionSk))
            .setSignaturePriv(ByteString.copyFrom(signatureSk))
            .setProposal(ByteString.copyFrom(MLSOutputStream.encode(proposal)))
            .setTransactionId(joinID)
            .build();

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void newMemberAddProposal(MlsClient.NewMemberAddProposalRequest request, StreamObserver<MlsClient.NewMemberAddProposalResponse> responseObserver)
    {
        catchWrap(new Function()
        {
            @Override
            public void run()
                throws Exception
            {
                newMemberAddProposalImpl(request, responseObserver);
            }
        }, responseObserver);
    }

    /**
     * @param request
     * @param responseObserver
     */
    private void createExternalSignerImpl(MlsClient.CreateExternalSignerRequest request, StreamObserver<MlsClient.CreateExternalSignerResponse> responseObserver)
        throws Exception
    {
        MlsCipherSuite suite = MlsCipherSuite.getSuite((short)request.getCipherSuite());
        AsymmetricCipherKeyPair sigSk = suite.generateSignatureKeyPair();
        Credential cred = Credential.forBasic(request.getIdentity().toByteArray());

        ExternalSender extSender = new ExternalSender(suite.serializeSignaturePublicKey(sigSk.getPublic()), cred);

        int signerID = storeSigner(suite.serializeSignaturePrivateKey(sigSk.getPrivate()));

        MlsClient.CreateExternalSignerResponse response = MlsClient.CreateExternalSignerResponse.newBuilder()
            .setExternalSender(ByteString.copyFrom(MLSOutputStream.encode(extSender)))
            .setSignerId(signerID)
            .build();

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void createExternalSigner(MlsClient.CreateExternalSignerRequest request, StreamObserver<MlsClient.CreateExternalSignerResponse> responseObserver)
    {
        catchWrap(new Function()
        {
            @Override
            public void run()
                throws Exception
            {
                createExternalSignerImpl(request, responseObserver);
            }
        }, responseObserver);
    }

    /**
     * @param request
     * @param responseObserver
     */
    private void addExternalSignerImpl(CachedGroup entry, MlsClient.AddExternalSignerRequest request, StreamObserver<MlsClient.ProposalResponse> responseObserver)
        throws Exception
    {
        byte[] extSender = request.getExternalSender().toByteArray();

        List<Extension> extList = new ArrayList<Extension>(entry.group.getExtensions());
        List<ExternalSender> extSenders = new ArrayList<ExternalSender>();
        for (Extension ext : extList)
        {
            if (ext.extensionType == ExtensionType.EXTERNAL_SENDERS)
            {
                extSenders = ext.getSenders();
            }
        }
        extList = new ArrayList<Extension>();
        extSenders.add((ExternalSender)MLSInputStream.decode(extSender, ExternalSender.class));
        extList.add(Extension.externalSender(extSenders));

        MLSMessage proposal = entry.group.groupContextExtensions(extList, entry.messageOptions);
        MlsClient.ProposalResponse response = MlsClient.ProposalResponse.newBuilder()
            .setProposal(ByteString.copyFrom(MLSOutputStream.encode(proposal)))
            .build();

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void addExternalSigner(MlsClient.AddExternalSignerRequest request, StreamObserver<MlsClient.ProposalResponse> responseObserver)
    {
        stateWrap(new FunctionWithState()
        {
            @Override
            public void run(CachedGroup group)
                throws Exception
            {
                addExternalSignerImpl(group, request, responseObserver);
            }
        }, request, responseObserver);
    }

    /**
     * @param request
     * @param responseObserver
     */
    private void externalSignerProposalImpl(MlsClient.ExternalSignerProposalRequest request, StreamObserver<MlsClient.ProposalResponse> responseObserver)
        throws Exception
    {
        byte[] groupMsgData = request.getGroupInfo().toByteArray();
        MLSMessage groupMsg = (MLSMessage)MLSInputStream.decode(groupMsgData, MLSMessage.class);
        GroupInfo groupInfo = groupMsg.groupInfo;

        MlsCipherSuite suite = groupInfo.getSuite();
        byte[] groupID = groupInfo.getGroupID();
        long epoch = groupInfo.getEpoch();

        byte[] treeData = request.getRatchetTree().toByteArray();
        TreeKEMPublicKey tree = (TreeKEMPublicKey)MLSInputStream.decode(treeData, TreeKEMPublicKey.class);

        // Look up the signer
        byte[] sigPriv = loadSigner(request.getSignerId());
        if (sigPriv == null)
        {
            throw new Exception("Unknown signer ID");
        }

        byte[] sigPub = suite.serializeSignaturePublicKey(suite.deserializeSignaturePrivateKey(sigPriv).getPublic());

        // Look up the signer index of this signer
        List<ExternalSender> extSenders = new ArrayList<ExternalSender>();
        for (Extension ext : groupInfo.getGroupContext().getExtensions())
        {
            if (ext.extensionType == ExtensionType.EXTERNAL_SENDERS)
            {
                extSenders = ext.getSenders();
            }
        }
        int sigIndex = -1;
        for (int i = 0; i < extSenders.size(); i++)
        {
            if (Arrays.equals(extSenders.get(i).getSignatureKey(), sigPub))
            {
                sigIndex = i;
            }
        }
        if (sigIndex == -1)
        {
            throw new Exception("Requested signer not allowed for this group");
        }

        // Sign the proposal
        Proposal proposal = proposalFromDescription(suite, groupID, tree, request.getDescription());
        MLSMessage signedProposal = MLSMessage.externalProposal(suite, groupID, epoch, proposal, sigIndex, sigPriv);

        MlsClient.ProposalResponse response = MlsClient.ProposalResponse.newBuilder()
            .setProposal(ByteString.copyFrom(MLSOutputStream.encode(signedProposal)))
            .build();

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void externalSignerProposal(MlsClient.ExternalSignerProposalRequest request, StreamObserver<MlsClient.ProposalResponse> responseObserver)
    {
        catchWrap(new Function()
        {
            @Override
            public void run()
                throws Exception
            {
                externalSignerProposalImpl(request, responseObserver);
            }
        }, responseObserver);
    }

    /**
     * <pre>
     * Cleanup
     * </pre>
     *
     * @param request
     * @param responseObserver
     */
    private void freeImpl(MlsClient.FreeRequest request, StreamObserver<MlsClient.FreeResponse> responseObserver)
        throws StatusException
    {
        int stateID = request.getStateId();
        if (!groupCache.containsKey(stateID))
        {
            throw Status.NOT_FOUND.withDescription("Unknown state").asException();
        }

        removeGroup(stateID);
        MlsClient.FreeResponse response = MlsClient.FreeResponse.newBuilder().build();
        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void free(MlsClient.FreeRequest request, StreamObserver<MlsClient.FreeResponse> responseObserver)
    {
        catchWrap(new Function()
        {
            @Override
            public void run()
                throws Exception
            {
                freeImpl(request, responseObserver);
            }
        }, responseObserver);
    }
}
