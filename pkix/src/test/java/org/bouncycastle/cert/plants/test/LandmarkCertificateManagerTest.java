package org.bouncycastle.cert.plants.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1RelativeOID;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.plants.MTCObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificateLogEntry;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.Validity;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.plants.LandmarkCertificateManager;
import org.bouncycastle.cert.plants.MTCSignature;
import org.bouncycastle.cert.plants.MerkleTreeCertificateValidator;
import org.bouncycastle.cert.plants.MerkleTreeHash;
import org.bouncycastle.cert.plants.MerkleTreePrimitives;
import org.bouncycastle.cert.plants.bc.BcMTCCosignerVerifierProvider;
import org.bouncycastle.cert.plants.bc.BcSha256MerkleTreeHash;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.util.test.SimpleTest;

public class LandmarkCertificateManagerTest
    extends SimpleTest
{
    private static final String LOG_TAID_STRING = "32473.1";

    private MerkleTreeHash hashFunc;
    private AsymmetricCipherKeyPair ecdsaKeyPair;
    private AsymmetricCipherKeyPair ed25519KeyPair;
    private byte[] logId;

    public void setUp()
        throws Exception
    {
        hashFunc = new BcSha256MerkleTreeHash();

        ECKeyPairGenerator ecGen = new ECKeyPairGenerator();
        X9ECParameters ecP = SECNamedCurves.getByName("secp256r1");
        ECNamedDomainParameters ecParams = new ECNamedDomainParameters(
            new ASN1ObjectIdentifier("1.2.840.10045.3.1.7"), ecP);
        ecGen.init(new ECKeyGenerationParameters(ecParams, new SecureRandom()));
        ecdsaKeyPair = ecGen.generateKeyPair();

        Ed25519PrivateKeyParameters edPriv = new Ed25519PrivateKeyParameters(new SecureRandom());
        Ed25519PublicKeyParameters edPub = edPriv.generatePublicKey();
        ed25519KeyPair = new AsymmetricCipherKeyPair(edPub, edPriv);

        logId = binaryTrustAnchorID(LOG_TAID_STRING);
    }

    public String getName()
    {
        return "LandmarkCertificateManagerTest";
    }

    public void performTest()
        throws Exception
    {
        setUp();
        testBuildLandmarkCertificate();
        testTrustedSubtreeManager();
        testCosignatureReplayThreshold();
    }

    private void testCosignatureReplayThreshold()
        throws Exception
    {
        byte[] cosignerId = binaryTrustAnchorID("32473.7");

        BcMTCCosignerVerifierProvider cosigners = new BcMTCCosignerVerifierProvider.Builder()
            .addCosigner(cosignerId, ed25519KeyPair.getPublic())
            .build();

        // Require two distinct trusted cosigners.
        LandmarkCertificateManager.TrustedSubtreeManager manager = new LandmarkCertificateManager.TrustedSubtreeManager(
            logId, hashFunc, cosigners, 2);

        long checkpointSize = 100;
        byte[] checkpointRoot = hashFunc.hashLeaf("checkpointRoot".getBytes());
        LandmarkCertificateManager.TrustedSubtreeManager.Checkpoint checkpoint =
            new LandmarkCertificateManager.TrustedSubtreeManager.Checkpoint(checkpointSize, checkpointRoot);

        byte[] signedData = buildCheckpointSignatureInput(logId, checkpointSize, checkpointRoot, cosignerId);
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, ed25519KeyPair.getPrivate());
        signer.update(signedData, 0, signedData.length);
        byte[] signature = signer.generateSignature();

        // One valid cosignature from a single trusted cosigner, replayed to fill the list. A 2-of-N
        // threshold must not be satisfied by one distinct cosigner.
        List<MTCSignature> replayed = new ArrayList<MTCSignature>();
        replayed.add(new MTCSignature(cosignerId, signature));
        replayed.add(new MTCSignature(cosignerId, signature));

        boolean added = manager.addLandmarkSubtree(
            0, checkpointSize, checkpointRoot, checkpoint, Collections.<byte[]>emptyList(), replayed);

        isTrue("Replayed cosignature must not satisfy the M-of-N threshold", !added);
        isEquals(0, manager.getTrustedSubtrees().size());
    }

    private void testBuildLandmarkCertificate()
        throws Exception
    {
        TBSCertificateLogEntry tbsEntry = createDummyTBSCertificateLogEntry();
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(ecdsaKeyPair.getPublic());

        long logNumber = 1;
        long index = 42;
        long start = 40;
        long end = 44;

        // Index 42 sits at relative position 2 of the size-4 landmark subtree
        // [40, 44), so the inclusion proof carries two nodes: the sibling leaf
        // 43 (combined on the right) and the node [40, 42) (combined on the left).
        byte[] leaf43 = hashFunc.hashLeaf("leaf43".getBytes());
        byte[] node4042 = hashFunc.hashNode(
            hashFunc.hashLeaf("leaf40".getBytes()), hashFunc.hashLeaf("leaf41".getBytes()));
        List<byte[]> inclusionProof = java.util.Arrays.asList(leaf43, node4042);

        MerkleTreePrimitives.SubtreeInfo landmarkSubtree = new MerkleTreePrimitives.SubtreeInfo(start, end);

        X509CertificateHolder cert = LandmarkCertificateManager.buildLandmarkCertificate(
            logNumber, index, tbsEntry, spki, landmarkSubtree, inclusionProof, hashFunc);

        AlgorithmIdentifier sigAlg = cert.getSignatureAlgorithm();
        isTrue("Signature algorithm is id-alg-mtcProof",
            MTCObjectIdentifiers.id_alg_mtcProof.equals(sigAlg.getAlgorithm()));
        isTrue("Signature algorithm parameters are absent", sigAlg.getParameters() == null);

        // The serial packs (log_number << 48) | index per Section 6.1.
        isEquals((logNumber << 48) | index, cert.getSerialNumber().longValue());

        // Decode the MTCProof from the signatureValue and confirm it carries no signatures.
        org.bouncycastle.cert.plants.MTCProof decoded =
            new org.bouncycastle.cert.plants.MTCProof(cert.getSignature());
        isEquals(start, decoded.getStart());
        isEquals(end, decoded.getEnd());
        isEquals(0, decoded.getSignatures().size());
        byte[] expectedProofBytes = new byte[leaf43.length + node4042.length];
        System.arraycopy(leaf43, 0, expectedProofBytes, 0, leaf43.length);
        System.arraycopy(node4042, 0, expectedProofBytes, leaf43.length, node4042.length);
        isTrue("Inclusion proof bytes preserved",
            areEqual(expectedProofBytes, decoded.getInclusionProof()));

        // Round-trip through the validator's trusted-subtree path (Section 7.2
        // step 11): a relying party that trusts (logNumber, [40, 44)) with the
        // hash the proof evaluates to must accept the certificate.
        byte[] entryHash = MerkleTreeCertificateValidator.computeEntryHash(cert, hashFunc);
        byte[] subtreeHash = MerkleTreePrimitives.evaluateSubtreeInclusionProof(
            index, start, end, entryHash, inclusionProof, hashFunc);

        MerkleTreeCertificateValidator.ValidationParams params =
            new MerkleTreeCertificateValidator.ValidationParams(
                new BcMTCCosignerVerifierProvider.Builder().build(),
                hashFunc,
                Collections.singletonList(new MerkleTreeCertificateValidator.TrustedSubtree(
                    logNumber, start, end, subtreeHash)),
                Collections.<MerkleTreeCertificateValidator.RevokedRange>emptyList(),
                1);

        isTrue("Landmark-relative certificate validates against the trusted subtree",
            MerkleTreeCertificateValidator.validateCertificate(cert, params));
    }

    private void testTrustedSubtreeManager()
        throws Exception
    {
        byte[] cosignerId = binaryTrustAnchorID("32473.7");

        BcMTCCosignerVerifierProvider cosigners = new BcMTCCosignerVerifierProvider.Builder()
            .addCosigner(cosignerId, ed25519KeyPair.getPublic())
            .build();

        LandmarkCertificateManager.TrustedSubtreeManager manager = new LandmarkCertificateManager.TrustedSubtreeManager(
            logId, hashFunc, cosigners, 1);

        long checkpointSize = 100;
        byte[] checkpointRoot = hashFunc.hashLeaf("checkpointRoot".getBytes());
        LandmarkCertificateManager.TrustedSubtreeManager.Checkpoint checkpoint =
            new LandmarkCertificateManager.TrustedSubtreeManager.Checkpoint(checkpointSize, checkpointRoot);

        byte[] signedData = buildCheckpointSignatureInput(logId, checkpointSize, checkpointRoot, cosignerId);
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, ed25519KeyPair.getPrivate());
        signer.update(signedData, 0, signedData.length);
        byte[] signature = signer.generateSignature();
        List<MTCSignature> checkpointSigs =
            Collections.singletonList(new MTCSignature(cosignerId, signature));

        // The trivial case: a subtree that exactly equals the checkpoint can be
        // accepted with an empty consistency proof.
        long subStart = 0;
        long subEnd = checkpointSize;
        byte[] subHash = checkpointRoot;
        List<byte[]> consistencyProof = Collections.emptyList();

        boolean added = manager.addLandmarkSubtree(
            subStart, subEnd, subHash, checkpoint, consistencyProof, checkpointSigs);
        isTrue("Landmark subtree added", added);

        List<LandmarkCertificateManager.TrustedSubtreeEntry> trusted = manager.getTrustedSubtrees();
        isEquals(1, trusted.size());
        LandmarkCertificateManager.TrustedSubtreeEntry entry = trusted.get(0);
        isEquals(subStart, entry.getStart());
        isEquals(subEnd, entry.getEnd());
        isTrue("Subtree hash matches", areEqual(subHash, entry.getHash()));

        // A tampered cosignature must be rejected.
        byte[] badSignature = signature.clone();
        badSignature[0] ^= 0x01;
        List<MTCSignature> badSigs = Collections.singletonList(new MTCSignature(cosignerId, badSignature));
        added = manager.addLandmarkSubtree(subStart, subEnd, subHash, checkpoint, consistencyProof, badSigs);
        isTrue("Tampered cosignature rejected", !added);
    }

    // ----- Helpers ----------------------------------------------------------

    private static byte[] binaryTrustAnchorID(String dotted)
        throws IOException
    {
        byte[] encoded = new ASN1RelativeOID(dotted).getEncoded();
        int lengthByte = encoded[1] & 0xFF;
        int contentOff;
        int contentLen;
        if ((lengthByte & 0x80) == 0)
        {
            contentLen = lengthByte;
            contentOff = 2;
        }
        else
        {
            int n = lengthByte & 0x7F;
            contentLen = 0;
            for (int i = 0; i < n; i++)
            {
                contentLen = (contentLen << 8) | (encoded[2 + i] & 0xFF);
            }
            contentOff = 2 + n;
        }
        byte[] out = new byte[contentLen];
        System.arraycopy(encoded, contentOff, out, 0, contentLen);
        return out;
    }

    /**
     * Builds a CosignedMessage for a checkpoint (start==0) per Section 5.3.1
     * of draft-04. The validator's TrustedSubtreeManager invokes the verifier
     * with {@code timestamp == 0}.
     */
    private byte[] buildCheckpointSignatureInput(byte[] logId, long treeSize, byte[] rootHash, byte[] cosignerId)
        throws IOException
    {
        byte[] cosignerName = asciiName(cosignerId);
        byte[] logOrigin = asciiName(logId);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write("subtree/v1\n\0".getBytes("ASCII"));   // 12-byte label
        baos.write((byte)cosignerName.length);
        baos.write(cosignerName);
        writeUint64(baos, 0L);                            // timestamp
        baos.write((byte)logOrigin.length);
        baos.write(logOrigin);
        writeUint64(baos, 0L);                            // start (checkpoint)
        writeUint64(baos, treeSize);                       // end
        baos.write(rootHash);
        return baos.toByteArray();
    }

    private static byte[] asciiName(byte[] binaryTrustAnchorID)
        throws IOException
    {
        String dotted = ASN1RelativeOID.fromContents(binaryTrustAnchorID).getId();
        return ("oid/1.3.6.1.4.1." + dotted).getBytes("US-ASCII");
    }

    private static void writeUint64(ByteArrayOutputStream baos, long v)
    {
        baos.write((byte)(v >>> 56));
        baos.write((byte)(v >>> 48));
        baos.write((byte)(v >>> 40));
        baos.write((byte)(v >>> 32));
        baos.write((byte)(v >>> 24));
        baos.write((byte)(v >>> 16));
        baos.write((byte)(v >>> 8));
        baos.write((byte)v);
    }

    private TBSCertificateLogEntry createDummyTBSCertificateLogEntry()
        throws IOException
    {
        AttributeTypeAndValue attr = new AttributeTypeAndValue(
            MTCObjectIdentifiers.id_rdna_trustAnchorID,
            new DERUTF8String(LOG_TAID_STRING));
        X500Name issuer = new X500Name(new RDN[]{new RDN(attr)});

        Time notBefore = new Time(new Date());
        Time notAfter = new Time(new Date(System.currentTimeMillis() + 86400000L));
        Validity validity = new Validity(notBefore, notAfter);

        X500Name subject = new X500Name("CN=test");
        AlgorithmIdentifier subjectPublicKeyAlgorithm = new AlgorithmIdentifier(
            new ASN1ObjectIdentifier("1.2.840.10045.2.1"));

        byte[] dummyKey = new byte[10];
        new SecureRandom().nextBytes(dummyKey);
        byte[] spkiHash = hashFunc.hashRaw(dummyKey);

        return new TBSCertificateLogEntry(
            new ASN1Integer(0), issuer, validity, subject,
            subjectPublicKeyAlgorithm, new DEROctetString(spkiHash),
            null, null, null);
    }

    public static void main(String[] args)
    {
        runTest(new LandmarkCertificateManagerTest());
    }
}
