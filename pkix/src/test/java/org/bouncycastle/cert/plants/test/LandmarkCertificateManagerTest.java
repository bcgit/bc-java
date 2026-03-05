package org.bouncycastle.cert.plants.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1RelativeOID;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificateLogEntry;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.Validity;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.plants.LandmarkCertificateManager;
import org.bouncycastle.cert.plants.MTCSignature;
import org.bouncycastle.cert.plants.MerkleTreeCertificateValidator;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.plants.MerkleTreePrimitives;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.util.test.SimpleTest;

public class LandmarkCertificateManagerTest extends SimpleTest
{
    private MerkleTreePrimitives.MerkleTreeHash hashFunc;
    private AsymmetricCipherKeyPair ecdsaKeyPair;
    private AsymmetricCipherKeyPair ed25519KeyPair;
    private byte[] logId;
    private ASN1ObjectIdentifier baseId;

    public void setUp() throws Exception
    {
        hashFunc = new MerkleTreePrimitives.Sha256MerkleTreeHash();

        // Generate keys (same as in main test)
        ECKeyPairGenerator ecGen = new ECKeyPairGenerator();
        X9ECParameters ecP = SECNamedCurves.getByName("secp256r1");
        ECNamedDomainParameters ecParams = new ECNamedDomainParameters(
            new ASN1ObjectIdentifier("1.2.840.10045.3.1.7"), ecP);
        ecGen.init(new ECKeyGenerationParameters(ecParams, new SecureRandom()));
        ecdsaKeyPair = ecGen.generateKeyPair();

        Ed25519PrivateKeyParameters edPriv = new Ed25519PrivateKeyParameters(new SecureRandom());
        Ed25519PublicKeyParameters edPub = edPriv.generatePublicKey();
        ed25519KeyPair = new AsymmetricCipherKeyPair(edPub, edPriv);

        logId = new ASN1RelativeOID("1.2.3").getEncoded();
        baseId = new ASN1ObjectIdentifier("1.2.3.100"); // dummy base for landmarks
    }

    @Override
    public String getName()
    {
        return "LandmarkCertificateManagerTest";
    }

    @Override
    public void performTest() throws Exception
    {
        setUp();
        testBuildLandmarkCertificate();
        testTrustedSubtreeManager();
    }

    private void testBuildLandmarkCertificate() throws Exception
    {
        // Create a dummy TBSCertificateLogEntry and SPKI
        TBSCertificateLogEntry tbsEntry = createDummyTBSCertificateLogEntry();
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(
            ecdsaKeyPair.getPublic());

        long index = 42;
        long start = 41;
        long end = 43;

        // Compute entry hash using validator's method (simplified)
        // In a real test, we'd build a full TBSCertificate first.
        // For simplicity, we'll just create a dummy entry hash.
        byte[] entryHash = hashFunc.hashLeaf("dummy".getBytes());

        // Inclusion proof for two‑leaf subtree
        byte[] siblingHash = hashFunc.hashLeaf("sibling".getBytes());
        List<byte[]> inclusionProof = Collections.singletonList(siblingHash);
        byte[] subtreeHash = hashFunc.hashNode(siblingHash, entryHash);

        MerkleTreePrimitives.SubtreeInfo landmarkSubtree = new MerkleTreePrimitives.SubtreeInfo(start, end);

        // Build landmark certificate
        X509CertificateHolder cert = LandmarkCertificateManager.buildLandmarkCertificate(
            index, tbsEntry, spki, landmarkSubtree, inclusionProof, hashFunc
        );

        // Verify it's a valid X.509 structure with our OID
        AlgorithmIdentifier sigAlg = cert.getSignatureAlgorithm();
        isTrue("Signature algorithm must be id-alg-mtcProof",
            MerkleTreeCertificateValidator.ID_ALG_MTC_PROOF.equals(sigAlg.getAlgorithm().getId()));

        // Check that serial number equals index
        isEquals(index, cert.getSerialNumber().longValue());

        // Optionally, decode MTCProof and verify it contains no signatures
        // (This would require making MTCProof parsing accessible)
    }

    private void testTrustedSubtreeManager() throws Exception
    {
        // Setup cosigners
        Map<MerkleTreeCertificateValidator.ByteArrayKey, AsymmetricKeyParameter> cosigners = new HashMap<>();
        byte[] cosignerId = new ASN1RelativeOID("1.2.3.7").getEncoded();
        cosigners.put(new MerkleTreeCertificateValidator.ByteArrayKey(cosignerId), ed25519KeyPair.getPublic());

        LandmarkCertificateManager.TrustedSubtreeManager manager = new LandmarkCertificateManager.TrustedSubtreeManager(
            logId, hashFunc, cosigners, 1 // min 1 cosignature
        );

        // Create a dummy checkpoint (tree size 100)
        long checkpointSize = 100;
        byte[] checkpointRoot = hashFunc.hashLeaf("checkpointRoot".getBytes());
        LandmarkCertificateManager.TrustedSubtreeManager.Checkpoint checkpoint =
            new LandmarkCertificateManager.TrustedSubtreeManager.Checkpoint(checkpointSize, checkpointRoot);

        // Sign checkpoint with Ed25519
        byte[] signedData = buildCheckpointSignatureInput(logId, checkpointSize, checkpointRoot, cosignerId);
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, ed25519KeyPair.getPrivate());
        signer.update(signedData, 0, signedData.length);
        byte[] signature = signer.generateSignature();
        List<MTCSignature> checkpointSigs =
            Collections.singletonList(new MTCSignature(cosignerId, signature));

        // Define a subtree that exactly matches the checkpoint (start=0, end=checkpointSize, hash=checkpointRoot)
        long subStart = 0;
        long subEnd = checkpointSize;
        byte[] subHash = checkpointRoot; // same hash

        // Consistency proof is empty because subtree equals checkpoint
        List<byte[]> consistencyProof = Collections.emptyList();

        // Add landmark subtree – should succeed
        boolean added = manager.addLandmarkSubtree(subStart, subEnd, subHash, checkpoint, consistencyProof, checkpointSigs);
        isTrue("Landmark subtree should be added", added);

        // Verify it appears in trusted list
        List<LandmarkCertificateManager.TrustedSubtreeEntry> trusted = manager.getTrustedSubtrees();
        isEquals(1, trusted.size());
        LandmarkCertificateManager.TrustedSubtreeEntry entry = trusted.get(0);
        isEquals(subStart, entry.getStart());
        isEquals(subEnd, entry.getEnd());
        isTrue("Subtree hash matches", areEqual(subHash, entry.getHash()));

        // Try adding with invalid cosignature (tamper signature)
        byte[] badSignature = signature.clone();
        badSignature[0] ^= 0x01;
        List<MTCSignature> badSigs =
            Collections.singletonList(new MTCSignature(cosignerId, badSignature));
        added = manager.addLandmarkSubtree(subStart, subEnd, subHash, checkpoint, consistencyProof, badSigs);
        isTrue("Addition should fail with invalid cosignature", !added);
    }

    private byte[] buildCheckpointSignatureInput(byte[] logId, long treeSize, byte[] rootHash, byte[] cosignerId) throws IOException
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write("mtc-subtree/v1\n\0".getBytes("ASCII"));
        baos.write((byte) cosignerId.length);
        baos.write(cosignerId);
        baos.write((byte) logId.length);
        baos.write(logId);
        writeUint64(baos, 0); // start = 0 for checkpoint
        writeUint64(baos, treeSize);
        baos.write(rootHash);
        return baos.toByteArray();
    }

    private void writeUint64(ByteArrayOutputStream baos, long v)
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

    private TBSCertificateLogEntry createDummyTBSCertificateLogEntry() throws IOException
    {
        ASN1ObjectIdentifier trustAnchorOid = X509Extension.id_rdna_trustAnchorID;
        ASN1RelativeOID logIdRelOid = new ASN1RelativeOID("1.2.3");
        AttributeTypeAndValue attr = new AttributeTypeAndValue(trustAnchorOid, logIdRelOid);
        X500Name issuer = new X500Name(new RDN[]{new RDN(attr)});

        Time notBefore = new Time(new Date());
        Time notAfter = new Time(new Date(System.currentTimeMillis() + 86400000L));
        Validity validity = new Validity(notBefore, notAfter);

        X500Name subject = new X500Name("CN=test");
        AlgorithmIdentifier subjectPublicKeyAlgorithm = new AlgorithmIdentifier(
            new ASN1ObjectIdentifier("1.2.840.10045.2.1"));

        byte[] dummyKey = new byte[10];
        new SecureRandom().nextBytes(dummyKey);
        byte[] spkiHash = hashFunc.hashLeaf(dummyKey);

        return new TBSCertificateLogEntry(
            new ASN1Integer(0), issuer, validity, subject,
            subjectPublicKeyAlgorithm, new DEROctetString(spkiHash),
            null, null, null
        );
    }

    public static void main(String[] args)
    {
        runTest(new LandmarkCertificateManagerTest());
    }
}
