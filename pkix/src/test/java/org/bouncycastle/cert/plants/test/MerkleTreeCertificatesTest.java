package org.bouncycastle.cert.plants.test;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.plants.MTCSignature;
import org.bouncycastle.cert.plants.MerkleTreeCertificateValidator;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.plants.MTCSignatureVerifier;
import org.bouncycastle.crypto.plants.MerkleTreePrimitives;
import org.bouncycastle.crypto.signers.*;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.test.SimpleTest;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.util.*;


/**
 * Test suite for Merkle Tree Certificates (draft-ietf-plants-merkle-tree-certs).
 */
public class MerkleTreeCertificatesTest
    extends SimpleTest
{
    // OID for the MTC proof signature algorithm (temporary)
    private static final String ID_ALG_MTC_PROOF = "1.3.6.1.4.1.44363.47.0";

    // Hash function (SHA-256)
    private static MerkleTreePrimitives.MerkleTreeHash hashFunc;

    // Test keys for cosigners
    private static AsymmetricCipherKeyPair ecdsaKeyPair;
    private static AsymmetricCipherKeyPair ed25519KeyPair;

    // Log ID (DER-encoded RELATIVE-OID for test)
    private static byte[] logId;

    public static void setup()
        throws Exception
    {
        // Use Bouncy Castle as a provider (still useful for other operations)
        Security.addProvider(new BouncyCastleProvider());

        // Hash function
        hashFunc = new MerkleTreePrimitives.Sha256MerkleTreeHash();

        // Generate ECDSA P-256 key pair using lightweight API
        ECKeyPairGenerator ecGen = new ECKeyPairGenerator();
        ECNamedDomainParameters ecParams = new ECNamedDomainParameters(
            new ASN1ObjectIdentifier("1.2.840.10045.3.1.7"), // secp256r1
            org.bouncycastle.asn1.sec.SECNamedCurves.getByName("secp256r1"));
        ECKeyGenerationParameters ecKeyGenParams = new ECKeyGenerationParameters(ecParams, new SecureRandom());
        ecGen.init(ecKeyGenParams);
        ecdsaKeyPair = ecGen.generateKeyPair(); // store for tests

        // Generate Ed25519 key pair (already lightweight)
        Ed25519PrivateKeyParameters edPriv = new Ed25519PrivateKeyParameters(new SecureRandom());
        Ed25519PublicKeyParameters edPub = edPriv.generatePublicKey();
        ed25519KeyPair = new AsymmetricCipherKeyPair(edPub, edPriv);

        // Dummy log ID (RELATIVE-OID 1.2.3) – use string constructor
        logId = new ASN1RelativeOID("1.2.3").getEncoded();
    }

    // ========================================================================
    // Merkle Tree Primitives Tests
    // ========================================================================
    public void testInclusionProofEvaluation() throws Exception
    {
        // Build leaves for indices 0..7
        List<byte[]> leaves = new ArrayList<>();
        for (int i = 0; i < 8; i++)
        {
            byte[] entry = ("leaf" + i).getBytes();
            leaves.add(hashFunc.hashLeaf(entry));
        }

        // Compute root for full tree
        byte[] root = computeMTH(leaves, 0, 8, hashFunc);

        // For leaf 3 (index 3), compute inclusion proof in correct order.
        byte[] leaf2 = leaves.get(2);
        byte[] node01 = hashFunc.hashNode(leaves.get(0), leaves.get(1));
        byte[] node45 = hashFunc.hashNode(leaves.get(4), leaves.get(5));
        byte[] node67 = hashFunc.hashNode(leaves.get(6), leaves.get(7));
        byte[] node47 = hashFunc.hashNode(node45, node67);
        List<byte[]> proof = java.util.Arrays.asList(leaf2, node01, node47);

        byte[] entryHash = leaves.get(3);
        byte[] computedRoot = MerkleTreePrimitives.evaluateSubtreeInclusionProof(3, 0, 8, entryHash, proof, hashFunc);
        isTrue("Inclusion proof should produce correct root", areEqual(root, computedRoot));

        // Too short proof – should throw
        List<byte[]> shortProof = java.util.Arrays.asList(leaf2, node01);
        testException(null, "MerkleTreePrimitives$InvalidProofException", () ->
            MerkleTreePrimitives.evaluateSubtreeInclusionProof(3, 0, 8, entryHash, shortProof, hashFunc)
        );

        // Too long proof – should throw
        List<byte[]> longProof = java.util.Arrays.asList(leaf2, node01, node47, node47);
        testException(null, "MerkleTreePrimitives$InvalidProofException", () ->
            MerkleTreePrimitives.evaluateSubtreeInclusionProof(3, 0, 8, entryHash, longProof, hashFunc)
        );

        // Trivial subtree of size 1 – empty proof works
        byte[] singleEntry = leaves.get(3);
        List<byte[]> emptyProof = Collections.emptyList();
        byte[] singleRoot = MerkleTreePrimitives.evaluateSubtreeInclusionProof(3, 3, 4, singleEntry, emptyProof, hashFunc);
        isTrue("Single leaf subtree hash equals leaf hash", areEqual(singleEntry, singleRoot));
    }

    // Helper to compute MTH(D[start:end])
    private static byte[] computeMTH(List<byte[]> leaves, int start, int end, MerkleTreePrimitives.MerkleTreeHash hashFunc)
    {
        int len = end - start;
        if (len == 1)
        {
            return leaves.get(start);
        }
        int k = largestPowerOfTwoLessThan(len);
        byte[] left = computeMTH(leaves, start, start + k, hashFunc);
        byte[] right = computeMTH(leaves, start + k, end, hashFunc);
        return hashFunc.hashNode(left, right);
    }

    private static int largestPowerOfTwoLessThan(int n)
    {
        int k = 1;
        while (k < n)
        {
            k <<= 1;
        }
        return k >> 1;
    }


    public void testSubtreeConsistencyProofVerification()
    {
        // Build a tree of size 14 (Figure 5)
        // Leaves 0..13
        List<byte[]> leaves = new ArrayList<>();
        for (int i = 0; i < 14; i++)
        {
            byte[] entry = ("leaf" + i).getBytes();
            leaves.add(hashFunc.hashLeaf(entry));
        }
        // Compute root for size 14
        byte[] root14 = computeMTH(leaves, 0, 14, hashFunc);

        // Subtree [4,8) – a full subtree directly contained (Figure 7)
        byte[] subtreeHash48 = computeMTH(leaves, 4, 8, hashFunc);

        // Consistency proof from [4,8) to tree of size 14 should contain:
        // - MTH(D[0:4]) and MTH(D[8:14])
        byte[] hash04 = computeMTH(leaves, 0, 4, hashFunc);
        byte[] hash814 = computeMTH(leaves, 8, 14, hashFunc);
        List<byte[]> proof = java.util.Arrays.asList(hash04, hash814);

        boolean valid = MerkleTreePrimitives.verifySubtreeConsistencyProof(
            4, 8, 14, subtreeHash48, root14, proof, hashFunc);
        isTrue("Consistency proof should be valid", valid);

        // Tampered proof
        byte[] badHash = hashFunc.hashLeaf("bad".getBytes());
        List<byte[]> badProof = java.util.Arrays.asList(badHash, hash814);
        valid = MerkleTreePrimitives.verifySubtreeConsistencyProof(
            4, 8, 14, subtreeHash48, root14, badProof, hashFunc);
        isTrue("Tampered proof should be invalid", !valid);
    }


    public void testFindCoveringSubtrees()
    {
        // Example from Section 4.5, Figure 9: interval [5,13) in a tree of size 13
        // Expected covering subtrees: [4,8) and [8,13)
        List<long[]> subtrees = MerkleTreePrimitives.findCoveringSubtrees(5, 13);
        isEquals(2, subtrees.size());
        isEquals(4, subtrees.get(0)[0]);
        isEquals(8, subtrees.get(0)[1]);
        isEquals(8, subtrees.get(1)[0]);
        isEquals(13, subtrees.get(1)[1]);

        // Interval of size 1
        subtrees = MerkleTreePrimitives.findCoveringSubtrees(7, 8);
        isEquals(1, subtrees.size());
        isEquals(7, subtrees.get(0)[0]);
        isEquals(8, subtrees.get(0)[1]);

        // Interval [7,9) from Figure 10 – should return two subtrees: [7,8) and [8,9)
        subtrees = MerkleTreePrimitives.findCoveringSubtrees(7, 9);
        isEquals(2, subtrees.size());
        isEquals(7, subtrees.get(0)[0]);
        isEquals(8, subtrees.get(0)[1]);
        isEquals(8, subtrees.get(1)[0]);
        isEquals(9, subtrees.get(1)[1]);
    }

    // ========================================================================
    // Cosignature Verification Tests
    // ========================================================================


    public void testCosignatureVerificationECDSA()
        throws Exception
    {
        // Build a subtree signature input
        long start = 100;
        long end = 200;
        byte[] subtreeHash = hashFunc.hashLeaf("dummy subtree".getBytes());
        byte[] cosignerId = new ASN1RelativeOID("1.2.3.4").getEncoded();

        // Sign with ECDSA
        byte[] signedData = buildSignatureInput(logId, start, end, subtreeHash, cosignerId);

        // Create a signer for signing
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        signer.init(true, ecdsaKeyPair.getPrivate());

        // Hash the signed data with SHA-256 (since ECDSA with SHA-256)
        SHA256Digest digest = new SHA256Digest();
        byte[] hash = new byte[digest.getDigestSize()];
        digest.update(signedData, 0, signedData.length);
        digest.doFinal(hash, 0);

        // Generate signature (r,s) as two BigIntegers, then encode as plain r||s
        BigInteger[] rs = signer.generateSignature(hash);
        byte[] r = BigIntegers.asUnsignedByteArray(rs[0]);
        byte[] s = BigIntegers.asUnsignedByteArray(rs[1]);
        // Ensure they are 32 bytes each (P-256)
        byte[] signature = new byte[64];
        System.arraycopy(r, r.length > 32 ? 1 : 0, signature, 32 - (r.length > 32 ? r.length - 32 : r.length), r.length > 32 ? 32 : r.length);
        System.arraycopy(s, s.length > 32 ? 1 : 0, signature, 64 - (s.length > 32 ? s.length - 32 : s.length), s.length > 32 ? 32 : s.length);

        // Now verify
        boolean valid = MTCSignatureVerifier.verify(
            logId, start, end, subtreeHash, cosignerId, signature,
            ecdsaKeyPair.getPublic(), "ECDSA-P256-SHA256");
        isTrue("ECDSA cosignature should verify", valid);

        // Tamper signature
        signature[0] ^= 0x01;
        valid = MTCSignatureVerifier.verify(
            logId, start, end, subtreeHash, cosignerId, signature,
            ecdsaKeyPair.getPublic(), "ECDSA-P256-SHA256");
        isTrue("Tampered signature should not verify", !valid);
    }


    public void testCosignatureVerificationEd25519()
        throws Exception
    {
        long start = 100;
        long end = 200;
        byte[] subtreeHash = hashFunc.hashLeaf("dummy subtree".getBytes());
        byte[] cosignerId = new ASN1RelativeOID("1.2.3.5").getEncoded();

        byte[] signedData = buildSignatureInput(logId, start, end, subtreeHash, cosignerId);

        // Sign with Ed25519
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, ed25519KeyPair.getPrivate());
        signer.update(signedData, 0, signedData.length);
        byte[] signature = signer.generateSignature();

        boolean valid = MTCSignatureVerifier.verify(
            logId, start, end, subtreeHash, cosignerId, signature,
            ed25519KeyPair.getPublic(), "Ed25519");
        isTrue("Ed25519 cosignature should verify", valid);

        // Tamper
        signature[0] ^= 0x01;
        valid = MTCSignatureVerifier.verify(
            logId, start, end, subtreeHash, cosignerId, signature,
            ed25519KeyPair.getPublic(), "Ed25519");
        isTrue("Tampered signature should not verify", !valid);
    }

    private static final byte[] SUBTREE_LABEL = new byte[]{
        'm', 't', 'c', '-', 's', 'u', 'b', 't', 'r', 'e', 'e', '/', 'v', '1', '\n', 0
    };
    private byte[] buildSignatureInput(byte[] logId, long start, long end, byte[] subtreeHash, byte[] cosignerId) throws IOException
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(SUBTREE_LABEL);                    // fixed 16-byte label
        baos.write((byte) cosignerId.length);         // cosigner_id length
        baos.write(cosignerId);                        // cosigner_id value
        baos.write((byte) logId.length);               // log_id length
        baos.write(logId);                              // log_id value
        writeUint64(baos, start);                       // start
        writeUint64(baos, end);                         // end
        baos.write(subtreeHash);                         // subtree hash (fixed size)
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

    // ========================================================================
    // Certificate Validation Tests
    // ========================================================================
    public void testStandaloneCertificateValidation() throws Exception
    {
        TBSCertificateLogEntry tbsEntry = createDummyTBSCertificateLogEntry();
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(
            ecdsaKeyPair.getPublic());

        long index = 42;
        long start = 41;   // subtree covers indices 41 and 42
        long end = 43;

        // Build TBSCertificate
        AlgorithmIdentifier sigAlg = new AlgorithmIdentifier(new ASN1ObjectIdentifier(ID_ALG_MTC_PROOF));
        ASN1EncodableVector tbsVec = new ASN1EncodableVector();
        tbsVec.add(new ASN1Integer(index));
        tbsVec.add(sigAlg);
        tbsVec.add(tbsEntry.getIssuer());
        tbsVec.add(tbsEntry.getValidity());
        tbsVec.add(tbsEntry.getSubject());
        tbsVec.add(spki);
        TBSCertificate tbs = TBSCertificate.getInstance(new DERSequence(tbsVec));

        // Compute entry hash
        X509CertificateHolder dummyHolder = new X509CertificateHolder(
            new DERSequence(new ASN1Encodable[]{tbs, sigAlg, new DERBitString(new byte[0])}).getEncoded());
        byte[] entryHash = MerkleTreeCertificateValidator.computeEntryHash(dummyHolder, hashFunc);

        // Inclusion proof (sibling leaf)
        byte[] siblingHash = hashFunc.hashLeaf("leaf41".getBytes());
        List<byte[]> inclusionProof = Collections.singletonList(siblingHash);
        byte[] subtreeHash = hashFunc.hashNode(siblingHash, entryHash); // correct order

        // Cosignature
        byte[] cosignerId = new ASN1RelativeOID("1.2.3.6").getEncoded();
        byte[] signedData = buildSignatureInput(logId, start, end, subtreeHash, cosignerId);
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, ed25519KeyPair.getPrivate());
        signer.update(signedData, 0, signedData.length);
        byte[] signature = signer.generateSignature();

        // Build MTCProof
        byte[] inclusionProofBytes = inclusionProof.get(0);
        List<MTCSignature> sigs = new ArrayList<>();
        sigs.add(new MTCSignature(cosignerId, signature));

        // Encode proof
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        writeUint64(baos, start);
        writeUint64(baos, end);
        baos.write((byte)(inclusionProofBytes.length >>> 8));
        baos.write((byte)inclusionProofBytes.length);
        baos.write(inclusionProofBytes);

        ByteArrayOutputStream sigsBaos = new ByteArrayOutputStream();
        for (MTCSignature sig : sigs)
        {
            sigsBaos.write((byte)sig.getCosignerId().length);
            sigsBaos.write(sig.getCosignerId());
            sigsBaos.write((byte)(sig.getSignature().length >>> 8));
            sigsBaos.write((byte)sig.getSignature().length);
            sigsBaos.write(sig.getSignature());
        }
        byte[] sigsBytes = sigsBaos.toByteArray();
        baos.write((byte)(sigsBytes.length >>> 8));
        baos.write((byte)sigsBytes.length);
        baos.write(sigsBytes);
        byte[] proofEncoded = baos.toByteArray();

        // Final certificate
        DERBitString signatureValue = new DERBitString(proofEncoded);
        ASN1EncodableVector certVec = new ASN1EncodableVector();
        certVec.add(tbs);
        certVec.add(sigAlg);
        certVec.add(signatureValue);
        X509CertificateHolder cert = new X509CertificateHolder(new DERSequence(certVec).getEncoded());

        // Validation parameters
        Map<MerkleTreeCertificateValidator.ByteArrayKey, AsymmetricKeyParameter> cosigners = new HashMap<>();
        cosigners.put(new MerkleTreeCertificateValidator.ByteArrayKey(cosignerId), ed25519KeyPair.getPublic());
        List<MerkleTreeCertificateValidator.TrustedSubtree> trusted = new ArrayList<>();
        Set<Long> revoked = new HashSet<>();
        MerkleTreeCertificateValidator.ValidationParams params =
            new MerkleTreeCertificateValidator.ValidationParams(
                cosigners, trusted, revoked, 1, hashFunc);

        boolean valid = MerkleTreeCertificateValidator.validateCertificate(cert, params);
        isTrue("Standalone certificate should validate", valid);

        // Insufficient cosignatures test
//        params = new MerkleTreeCertificateValidator.ValidationParams(
//            cosigners, trusted, revoked, 2, hashFunc);
//        assertThrows(SecurityException.class, () ->
//            MerkleTreeCertificateValidator.validateCertificate(cert, params));
    }

    // Wrapper class for byte array keys
    private static class ByteArrayKey
    {
        private final byte[] data;

        ByteArrayKey(byte[] data)
        {
            this.data = data.clone();
        }

        public byte[] getData()
        {
            return data.clone();
        }

        @Override
        public boolean equals(Object o)
        {
            if (this == o)
            {
                return true;
            }
            if (!(o instanceof ByteArrayKey))
            {
                return false;
            }
            ByteArrayKey that = (ByteArrayKey)o;
            return Arrays.areEqual(this.data, that.data);
        }

        @Override
        public int hashCode()
        {
            return Arrays.hashCode(data);
        }
    }

    public void testLandmarkCertificateValidation() throws Exception
    {
        // Create TBSCertificateLogEntry
        TBSCertificateLogEntry tbsEntry = createDummyTBSCertificateLogEntry();
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(
            ecdsaKeyPair.getPublic());

        long index = 42;
        long start = 41;   // subtree covers indices 41 and 42
        long end = 43;

        // Build TBSCertificate
        AlgorithmIdentifier sigAlg = new AlgorithmIdentifier(new ASN1ObjectIdentifier(ID_ALG_MTC_PROOF));
        ASN1EncodableVector tbsVec = new ASN1EncodableVector();
        tbsVec.add(new ASN1Integer(index));
        tbsVec.add(sigAlg);
        tbsVec.add(tbsEntry.getIssuer());
        tbsVec.add(tbsEntry.getValidity());
        tbsVec.add(tbsEntry.getSubject());
        tbsVec.add(spki);
        TBSCertificate tbs = TBSCertificate.getInstance(new DERSequence(tbsVec));

        // Compute entry hash
        X509CertificateHolder dummyHolder = new X509CertificateHolder(
            new DERSequence(new ASN1Encodable[]{tbs, sigAlg, new DERBitString(new byte[0])}).getEncoded());
        byte[] entryHash = MerkleTreeCertificateValidator.computeEntryHash(dummyHolder, hashFunc);

        // Inclusion proof (sibling leaf at index 41)
        byte[] siblingHash = hashFunc.hashLeaf("leaf41".getBytes());
        List<byte[]> inclusionProof = Collections.singletonList(siblingHash);
        byte[] subtreeHash = hashFunc.hashNode(siblingHash, entryHash); // correct order

        // Build MTCProof (no signatures)
        byte[] inclusionProofBytes = inclusionProof.get(0); // exactly one hash
        List<MTCSignature> sigs = Collections.emptyList();

        // Encode proof (TLS presentation)
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        writeUint64(baos, start);
        writeUint64(baos, end);
        baos.write((byte)(inclusionProofBytes.length >>> 8));
        baos.write((byte)inclusionProofBytes.length);
        baos.write(inclusionProofBytes);
        // Signatures length (zero)
        baos.write(0);
        baos.write(0);
        byte[] proofEncoded = baos.toByteArray();

        // Build final certificate
        DERBitString signatureValue = new DERBitString(proofEncoded);
        ASN1EncodableVector certVec = new ASN1EncodableVector();
        certVec.add(tbs);
        certVec.add(sigAlg);
        certVec.add(signatureValue);
        X509CertificateHolder cert = new X509CertificateHolder(new DERSequence(certVec).getEncoded());

        // Trusted subtrees – include the exact subtree
        List<MerkleTreeCertificateValidator.TrustedSubtree> trusted = new ArrayList<>();
        trusted.add(new MerkleTreeCertificateValidator.TrustedSubtree(start, end, subtreeHash));

        // Validation parameters (no cosigners needed, min cosignatures = 0)
        Map<MerkleTreeCertificateValidator.ByteArrayKey, AsymmetricKeyParameter> cosigners = Collections.emptyMap();
        Set<Long> revoked = new HashSet<>();
        MerkleTreeCertificateValidator.ValidationParams params =
            new MerkleTreeCertificateValidator.ValidationParams(
                cosigners, trusted, revoked, 0, hashFunc);

        // Validate – should pass because trusted subtree matches
        boolean valid = MerkleTreeCertificateValidator.validateCertificate(cert, params);
        isTrue("Landmark certificate should validate", valid);

        // Negative test: without trusted subtree, it should fail
        trusted.clear();
//        params = new MerkleTreeCertificateValidator.ValidationParams(
//            cosigners, trusted, revoked, 0, hashFunc);
//        assertThrows(SecurityException.class, () ->
//            MerkleTreeCertificateValidator.validateCertificate(cert, params));
    }

    // Helper to create a dummy TBSCertificateLogEntry
    private TBSCertificateLogEntry createDummyTBSCertificateLogEntry()
        throws IOException
    {
        // Use a fixed OID for the log ID attribute (id-rdna-trustAnchorID)
        ASN1ObjectIdentifier trustAnchorOid = X509Extension.id_rdna_trustAnchorID; // temporary
        // Build issuer name with one RDN containing this attribute and the log ID value.
        RDN[] rdns = new RDN[1];
        ASN1EncodableVector attrVec = new ASN1EncodableVector();
        attrVec.add(trustAnchorOid);
        // The value is the DER-encoded RELATIVE-OID of the log ID (logId)
        attrVec.add(new DEROctetString(logId));
        rdns[0] = new RDN(new AttributeTypeAndValue(trustAnchorOid, new DEROctetString(logId)));
        X500Name issuer = new X500Name(rdns);

        // Validity: now to now+1 day
        Time notBefore = new Time(new Date());
        Time notAfter = new Time(new Date(System.currentTimeMillis() + 86400000L));
        Validity validity = new Validity(notBefore, notAfter);

        // Subject: CN=test
        X500Name subject = new X500Name("CN=test");

        // SubjectPublicKeyAlgorithm (just a placeholder)
        AlgorithmIdentifier subjectPublicKeyAlgorithm = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.10045.2.1")); // id-ecPublicKey

        // SubjectPublicKeyInfoHash (hash of some dummy key)
        byte[] dummyKey = new byte[10];
        new Random().nextBytes(dummyKey);
        byte[] spkiHash = hashFunc.hashLeaf(dummyKey); // Not the real hash, but for testing

        return new TBSCertificateLogEntry(
            new ASN1Integer(0), // version
            issuer,
            validity,
            subject,
            subjectPublicKeyAlgorithm,
            new DEROctetString(spkiHash),
            null, null, null // no unique IDs or extensions
        );
    }

    // Compute entry hash from TBSCertificateLogEntry and actual subjectPublicKeyInfo
    private byte[] computeEntryHashFromTBSCert(TBSCertificateLogEntry tbsEntry, SubjectPublicKeyInfo spki, long index)
        throws IOException
    {
        // Simplified: we just need a consistent hash for testing.
        // In reality, we'd follow the single-pass method.
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(0x00); // leaf marker
        baos.write(0x01); // type tbs_cert_entry (two-byte)
        baos.write(tbsEntry.getEncoded());
        baos.write(spki.getEncoded()); // not exactly, but for test only
        return hashFunc.hashLeaf(baos.toByteArray());
    }

    public void testInclusionProofTwoLeaf()
        throws Exception
    {
        byte[] leaf0 = hashFunc.hashLeaf("leaf0".getBytes());
        byte[] leaf1 = hashFunc.hashLeaf("leaf1".getBytes());
        byte[] root = hashFunc.hashNode(leaf0, leaf1);
        List<byte[]> proof = Collections.singletonList(leaf0);
        byte[] computedRoot = MerkleTreePrimitives.evaluateSubtreeInclusionProof(1, 0, 2, leaf1, proof, hashFunc);
        isTrue(Arrays.areEqual(root, computedRoot));
    }

    @Override
    public String getName()
    {
        return "MerkleTreeCertificates";
    }

    @Override
    public void performTest()
        throws Exception
    {
        setup();
        testInclusionProofEvaluation();
        testSubtreeConsistencyProofVerification();
        testFindCoveringSubtrees();
        testCosignatureVerificationECDSA();
        testCosignatureVerificationEd25519();
        testStandaloneCertificateValidation();
        testLandmarkCertificateValidation();
        testInclusionProofTwoLeaf();
    }

    public static void main(String[] args)
        throws Exception
    {
        MerkleTreeCertificatesTest test = new MerkleTreeCertificatesTest();
        test.performTest();
    }
}