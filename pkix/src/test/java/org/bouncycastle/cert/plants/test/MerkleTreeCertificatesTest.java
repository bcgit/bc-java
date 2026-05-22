package org.bouncycastle.cert.plants.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1RelativeOID;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.plants.CloudFlareObjectIdentifiers;
import org.bouncycastle.asn1.plants.MTCSignature;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.TBSCertificateLogEntry;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.Validity;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.plants.MerkleTreeCertificateValidator;
import org.bouncycastle.cert.plants.bc.BcMTCCosignerVerifierProvider;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.plants.MTCSignatureVerifier;
import org.bouncycastle.crypto.plants.MerkleTreePrimitives;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Tests for the Merkle Tree Certificates implementation, exercising the
 * primitives, cosignature verification, and full certificate validation paths
 * defined by draft-ietf-plants-merkle-tree-certs-03.
 */
public class MerkleTreeCertificatesTest
    extends SimpleTest
{
    private static final String LOG_TAID_STRING = "32473.1";

    private MerkleTreePrimitives.MerkleTreeHash hashFunc;
    private AsymmetricCipherKeyPair ecdsaKeyPair;
    private AsymmetricCipherKeyPair ed25519KeyPair;
    private byte[] logId;

    public void setup()
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        hashFunc = new MerkleTreePrimitives.Sha256MerkleTreeHash();

        ECKeyPairGenerator ecGen = new ECKeyPairGenerator();
        ECNamedDomainParameters ecParams = new ECNamedDomainParameters(
            new ASN1ObjectIdentifier("1.2.840.10045.3.1.7"),
            SECNamedCurves.getByName("secp256r1"));
        ecGen.init(new ECKeyGenerationParameters(ecParams, new SecureRandom()));
        ecdsaKeyPair = ecGen.generateKeyPair();

        Ed25519PrivateKeyParameters edPriv = new Ed25519PrivateKeyParameters(new SecureRandom());
        Ed25519PublicKeyParameters edPub = edPriv.generatePublicKey();
        ed25519KeyPair = new AsymmetricCipherKeyPair(edPub, edPriv);

        // Binary trust anchor ID per draft-ietf-tls-trust-anchor-ids Section 3:
        // the base-128 OID-component bytes only, no ASN.1 tag or length.
        logId = binaryTrustAnchorID(LOG_TAID_STRING);
    }

    public void testInclusionProofEvaluation()
        throws Exception
    {
        List<byte[]> leaves = new ArrayList<byte[]>();
        for (int i = 0; i < 8; i++)
        {
            leaves.add(hashFunc.hashLeaf(("leaf" + i).getBytes()));
        }

        byte[] root = computeMTH(leaves, 0, 8, hashFunc);

        // Inclusion proof for leaf 3 in [0, 8): siblings going up are leaf 2,
        // hash(leaf 0, leaf 1), and hash([4, 6), [6, 8)).
        byte[] leaf2 = leaves.get(2);
        byte[] node01 = hashFunc.hashNode(leaves.get(0), leaves.get(1));
        byte[] node45 = hashFunc.hashNode(leaves.get(4), leaves.get(5));
        byte[] node67 = hashFunc.hashNode(leaves.get(6), leaves.get(7));
        byte[] node47 = hashFunc.hashNode(node45, node67);
        List<byte[]> proof = Arrays.asList(leaf2, node01, node47);

        byte[] entryHash = leaves.get(3);
        byte[] computedRoot = MerkleTreePrimitives.evaluateSubtreeInclusionProof(
            3, 0, 8, entryHash, proof, hashFunc);
        isTrue("Inclusion proof produces the correct root", areEqual(root, computedRoot));

        final List<byte[]> shortProof = Arrays.asList(leaf2, node01);
        testException(null, "MerkleTreePrimitives$InvalidProofException", new TestExceptionOperation()
        {
            public void operation()
                throws Exception
            {
                MerkleTreePrimitives.evaluateSubtreeInclusionProof(3, 0, 8, entryHash, shortProof, hashFunc);
            }
        });

        final List<byte[]> longProof = Arrays.asList(leaf2, node01, node47, node47);
        testException(null, "MerkleTreePrimitives$InvalidProofException", new TestExceptionOperation()
        {
            public void operation()
                throws Exception
            {
                MerkleTreePrimitives.evaluateSubtreeInclusionProof(3, 0, 8, entryHash, longProof, hashFunc);
            }
        });

        // Trivial subtree of size 1 with empty proof returns entry_hash itself.
        byte[] singleRoot = MerkleTreePrimitives.evaluateSubtreeInclusionProof(
            3, 3, 4, leaves.get(3), Collections.<byte[]>emptyList(), hashFunc);
        isTrue("Single-leaf subtree hash equals leaf hash", areEqual(leaves.get(3), singleRoot));

        // [start, end) with start not a multiple of BIT_CEIL(end - start) must fail Section 4.1.
        testException(null, "MerkleTreePrimitives$InvalidProofException", new TestExceptionOperation()
        {
            public void operation()
                throws Exception
            {
                // [3, 5) has size 2, requiring start to be a multiple of 2.
                MerkleTreePrimitives.evaluateSubtreeInclusionProof(
                    3, 3, 5, entryHash, Collections.<byte[]>emptyList(), hashFunc);
            }
        });
    }

    public void testSubtreeConsistencyProofVerification()
    {
        // Example from Section 4.4 Figure 7: subtree [4, 8) inside a tree of size 14.
        List<byte[]> leaves = new ArrayList<byte[]>();
        for (int i = 0; i < 14; i++)
        {
            leaves.add(hashFunc.hashLeaf(("leaf" + i).getBytes()));
        }
        byte[] root14 = computeMTH(leaves, 0, 14, hashFunc);
        byte[] subtreeHash48 = computeMTH(leaves, 4, 8, hashFunc);

        byte[] hash04 = computeMTH(leaves, 0, 4, hashFunc);
        byte[] hash814 = computeMTH(leaves, 8, 14, hashFunc);
        List<byte[]> proof = Arrays.asList(hash04, hash814);

        isTrue("Consistency proof valid", MerkleTreePrimitives.verifySubtreeConsistencyProof(
            4, 8, 14, subtreeHash48, root14, proof, hashFunc));

        byte[] badHash = hashFunc.hashLeaf("bad".getBytes());
        isTrue("Tampered consistency proof rejected", !MerkleTreePrimitives.verifySubtreeConsistencyProof(
            4, 8, 14, subtreeHash48, root14, Arrays.asList(badHash, hash814), hashFunc));

        // Figure 8: subtree [8, 13) inside a tree of size 14 (subtree not directly
        // contained in the tree -- exercises the LSB-of-sn shift path in
        // Section 4.4.3 step 7.2.3, which is where the previous implementation
        // had the loop condition reversed.
        byte[] subtreeHash813 = computeMTH(leaves, 8, 13, hashFunc);
        byte[] hashD12 = leaves.get(12);
        byte[] hashD13 = leaves.get(13);
        byte[] hash812 = computeMTH(leaves, 8, 12, hashFunc);
        byte[] hash08 = computeMTH(leaves, 0, 8, hashFunc);
        List<byte[]> proof813 = Arrays.asList(hashD12, hashD13, hash812, hash08);

        isTrue("Consistency proof for partial subtree valid",
            MerkleTreePrimitives.verifySubtreeConsistencyProof(
                8, 13, 14, subtreeHash813, root14, proof813, hashFunc));
    }

    public void testFindCoveringSubtrees()
    {
        List<long[]> subtrees = MerkleTreePrimitives.findCoveringSubtrees(5, 13);
        isEquals(2, subtrees.size());
        isEquals(4, subtrees.get(0)[0]);
        isEquals(8, subtrees.get(0)[1]);
        isEquals(8, subtrees.get(1)[0]);
        isEquals(13, subtrees.get(1)[1]);

        subtrees = MerkleTreePrimitives.findCoveringSubtrees(7, 8);
        isEquals(1, subtrees.size());
        isEquals(7, subtrees.get(0)[0]);
        isEquals(8, subtrees.get(0)[1]);

        subtrees = MerkleTreePrimitives.findCoveringSubtrees(7, 9);
        isEquals(2, subtrees.size());
        isEquals(7, subtrees.get(0)[0]);
        isEquals(8, subtrees.get(0)[1]);
        isEquals(8, subtrees.get(1)[0]);
        isEquals(9, subtrees.get(1)[1]);
    }

    public void testValidSubtreeCheck()
    {
        // Powers-of-two-aligned starts are always valid.
        isTrue("[0, 4) is valid", MerkleTreePrimitives.isValidSubtree(0, 4));
        isTrue("[4, 8) is valid", MerkleTreePrimitives.isValidSubtree(4, 8));
        isTrue("[8, 13) is valid", MerkleTreePrimitives.isValidSubtree(8, 13));

        // Misaligned starts must be rejected.
        isTrue("[3, 5) is invalid (start not multiple of 2)", !MerkleTreePrimitives.isValidSubtree(3, 5));
        isTrue("[6, 10) is invalid (start not multiple of 4)", !MerkleTreePrimitives.isValidSubtree(6, 10));

        // Degenerate ranges.
        isTrue("end == start is invalid", !MerkleTreePrimitives.isValidSubtree(5, 5));
        isTrue("end < start is invalid", !MerkleTreePrimitives.isValidSubtree(10, 5));
        isTrue("negative start is invalid", !MerkleTreePrimitives.isValidSubtree(-1, 5));
    }

    public void testCosignatureVerificationECDSA()
        throws Exception
    {
        long start = 100;
        long end = 200;
        byte[] subtreeHash = hashFunc.hashLeaf("dummy subtree".getBytes());
        byte[] cosignerId = binaryTrustAnchorID("32473.2");

        byte[] signedData = buildSignatureInput(logId, start, end, subtreeHash, cosignerId);

        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        signer.init(true, ecdsaKeyPair.getPrivate());

        SHA256Digest digest = new SHA256Digest();
        byte[] hash = new byte[digest.getDigestSize()];
        digest.update(signedData, 0, signedData.length);
        digest.doFinal(hash, 0);

        BigInteger[] rs = signer.generateSignature(hash);
        byte[] r = BigIntegers.asUnsignedByteArray(32, rs[0]);
        byte[] s = BigIntegers.asUnsignedByteArray(32, rs[1]);
        byte[] signature = new byte[64];
        System.arraycopy(r, 0, signature, 0, 32);
        System.arraycopy(s, 0, signature, 32, 32);

        isTrue("ECDSA cosignature verifies", MTCSignatureVerifier.verify(
            logId, start, end, subtreeHash, cosignerId, signature,
            ecdsaKeyPair.getPublic(), "ECDSA-P256-SHA256"));

        signature[0] ^= 0x01;
        isTrue("Tampered ECDSA signature rejected", !MTCSignatureVerifier.verify(
            logId, start, end, subtreeHash, cosignerId, signature,
            ecdsaKeyPair.getPublic(), "ECDSA-P256-SHA256"));
    }

    public void testCosignatureVerificationEd25519()
        throws Exception
    {
        long start = 100;
        long end = 200;
        byte[] subtreeHash = hashFunc.hashLeaf("dummy subtree".getBytes());
        byte[] cosignerId = binaryTrustAnchorID("32473.3");

        byte[] signedData = buildSignatureInput(logId, start, end, subtreeHash, cosignerId);

        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, ed25519KeyPair.getPrivate());
        signer.update(signedData, 0, signedData.length);
        byte[] signature = signer.generateSignature();

        isTrue("Ed25519 cosignature verifies", MTCSignatureVerifier.verify(
            logId, start, end, subtreeHash, cosignerId, signature,
            ed25519KeyPair.getPublic(), "Ed25519"));

        signature[0] ^= 0x01;
        isTrue("Tampered Ed25519 signature rejected", !MTCSignatureVerifier.verify(
            logId, start, end, subtreeHash, cosignerId, signature,
            ed25519KeyPair.getPublic(), "Ed25519"));
    }

    public void testStandaloneCertificateValidation()
        throws Exception
    {
        TBSCertificateLogEntry tbsEntry = createDummyTBSCertificateLogEntry();
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(ecdsaKeyPair.getPublic());

        // [42, 44) is a valid subtree per Section 4.1: start (42) is a multiple
        // of BIT_CEIL(end - start) = BIT_CEIL(2) = 2.
        final long logNumber = 1;
        final long index = 42;
        final long serial = (logNumber << 48) | index;  // Section 6.1 of draft-04
        long start = 42;
        long end = 44;
        // Construct the log ID by appending OID components 0 and logNumber to
        // the CA ID, matching what the validator will compute.
        byte[] cosignedLogId = binaryLogId(LOG_TAID_STRING, logNumber);

        AlgorithmIdentifier sigAlg = new AlgorithmIdentifier(CloudFlareObjectIdentifiers.id_alg_mtcProof);
        TBSCertificate tbs = buildTBSCertificate(tbsEntry, serial, sigAlg, spki);

        // Compute the entry hash from the TBS by way of a synthetic certificate (we
        // do not have an MTCProof yet, so use an empty BIT STRING placeholder).
        X509CertificateHolder dummyHolder = new X509CertificateHolder(
            new DERSequence(new ASN1Encodable[]{tbs, sigAlg, new DERBitString(new byte[0])}).getEncoded());
        byte[] entryHash = MerkleTreeCertificateValidator.computeEntryHash(dummyHolder, hashFunc);

        // The entry sits at fn=0 within [42, 44), so the proof's sole sibling
        // (leaf 43) is to the right of the entry hash.
        byte[] siblingHash = hashFunc.hashLeaf("leaf43".getBytes());
        byte[] subtreeHash = hashFunc.hashNode(entryHash, siblingHash);

        byte[] cosignerId = binaryTrustAnchorID("32473.4");
        byte[] signedData = buildSignatureInput(cosignedLogId, start, end, subtreeHash, cosignerId);
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, ed25519KeyPair.getPrivate());
        signer.update(signedData, 0, signedData.length);
        byte[] signature = signer.generateSignature();

        List<MTCSignature> sigs = Collections.singletonList(new MTCSignature(cosignerId, signature));
        org.bouncycastle.cert.plants.MTCProof proof = new org.bouncycastle.cert.plants.MTCProof(
            start, end, siblingHash, sigs);

        DERBitString signatureValue = new DERBitString(proof.encode());
        final X509CertificateHolder cert = new X509CertificateHolder(
            new DERSequence(new ASN1Encodable[]{tbs, sigAlg, signatureValue}).getEncoded());

        BcMTCCosignerVerifierProvider cosigners = new BcMTCCosignerVerifierProvider.Builder()
            .addCosigner(cosignerId, ed25519KeyPair.getPublic())
            .build();

        MerkleTreeCertificateValidator.ValidationParams params =
            new MerkleTreeCertificateValidator.ValidationParams(
                cosigners,
                Collections.<MerkleTreeCertificateValidator.TrustedSubtree>emptyList(),
                new HashSet<Long>(),
                1,
                hashFunc);

        isTrue("Standalone certificate validates", MerkleTreeCertificateValidator.validateCertificate(cert, params));

        // Tightening the policy beyond what the certificate carries must fail.
        final MerkleTreeCertificateValidator.ValidationParams strict =
            new MerkleTreeCertificateValidator.ValidationParams(
                cosigners,
                Collections.<MerkleTreeCertificateValidator.TrustedSubtree>emptyList(),
                new HashSet<Long>(),
                2,
                hashFunc);
        testException("Insufficient valid cosignatures", "SecurityException", new TestExceptionOperation()
        {
            public void operation()
                throws Exception
            {
                MerkleTreeCertificateValidator.validateCertificate(cert, strict);
            }
        });

        // Revoking the index must fail validation.
        Set<Long> revoked = new HashSet<Long>();
        revoked.add(Long.valueOf(index));   // the lower 48 bits of the serial
        final MerkleTreeCertificateValidator.ValidationParams revokedParams =
            new MerkleTreeCertificateValidator.ValidationParams(
                cosigners,
                Collections.<MerkleTreeCertificateValidator.TrustedSubtree>emptyList(),
                revoked,
                1,
                hashFunc);
        testException("revoked", "SecurityException", new TestExceptionOperation()
        {
            public void operation()
                throws Exception
            {
                MerkleTreeCertificateValidator.validateCertificate(cert, revokedParams);
            }
        });
    }

    public void testLandmarkCertificateValidation()
        throws Exception
    {
        TBSCertificateLogEntry tbsEntry = createDummyTBSCertificateLogEntry();
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(ecdsaKeyPair.getPublic());

        final long logNumber = 1;
        long index = 42;
        long serial = (logNumber << 48) | index;
        long start = 42;
        long end = 44;

        AlgorithmIdentifier sigAlg = new AlgorithmIdentifier(CloudFlareObjectIdentifiers.id_alg_mtcProof);
        TBSCertificate tbs = buildTBSCertificate(tbsEntry, serial, sigAlg, spki);

        X509CertificateHolder dummyHolder = new X509CertificateHolder(
            new DERSequence(new ASN1Encodable[]{tbs, sigAlg, new DERBitString(new byte[0])}).getEncoded());
        byte[] entryHash = MerkleTreeCertificateValidator.computeEntryHash(dummyHolder, hashFunc);

        byte[] siblingHash = hashFunc.hashLeaf("leaf43".getBytes());
        byte[] subtreeHash = hashFunc.hashNode(entryHash, siblingHash);

        org.bouncycastle.cert.plants.MTCProof proof = new org.bouncycastle.cert.plants.MTCProof(
            start, end, siblingHash, Collections.<MTCSignature>emptyList());

        DERBitString signatureValue = new DERBitString(proof.encode());
        final X509CertificateHolder cert = new X509CertificateHolder(
            new DERSequence(new ASN1Encodable[]{tbs, sigAlg, signatureValue}).getEncoded());

        List<MerkleTreeCertificateValidator.TrustedSubtree> trusted = new ArrayList<MerkleTreeCertificateValidator.TrustedSubtree>();
        trusted.add(new MerkleTreeCertificateValidator.TrustedSubtree(start, end, subtreeHash));

        MerkleTreeCertificateValidator.ValidationParams params =
            new MerkleTreeCertificateValidator.ValidationParams(
                new BcMTCCosignerVerifierProvider.Builder().build(),
                trusted,
                new HashSet<Long>(),
                1,
                hashFunc);

        isTrue("Landmark certificate validates", MerkleTreeCertificateValidator.validateCertificate(cert, params));

        // No matching trusted subtree => fall through to cosignature checks (none here) => fail.
        final MerkleTreeCertificateValidator.ValidationParams noTrusted =
            new MerkleTreeCertificateValidator.ValidationParams(
                new BcMTCCosignerVerifierProvider.Builder().build(),
                Collections.<MerkleTreeCertificateValidator.TrustedSubtree>emptyList(),
                new HashSet<Long>(),
                1,
                hashFunc);
        testException("Insufficient", "SecurityException", new TestExceptionOperation()
        {
            public void operation()
                throws Exception
            {
                MerkleTreeCertificateValidator.validateCertificate(cert, noTrusted);
            }
        });

        // Trusted subtree with matching [start, end) but wrong hash must reject
        // outright per Section 7.2 step 7 (no fall-through to cosignatures).
        List<MerkleTreeCertificateValidator.TrustedSubtree> badHashTrusted =
            new ArrayList<MerkleTreeCertificateValidator.TrustedSubtree>();
        badHashTrusted.add(new MerkleTreeCertificateValidator.TrustedSubtree(
            start, end, hashFunc.hashLeaf("not the right hash".getBytes())));
        final MerkleTreeCertificateValidator.ValidationParams badHash =
            new MerkleTreeCertificateValidator.ValidationParams(
                new BcMTCCosignerVerifierProvider.Builder().build(),
                badHashTrusted,
                new HashSet<Long>(),
                1,
                hashFunc);
        testException("does not match the trusted subtree", "SecurityException", new TestExceptionOperation()
        {
            public void operation()
                throws Exception
            {
                MerkleTreeCertificateValidator.validateCertificate(cert, badHash);
            }
        });
    }

    public void testInclusionProofTwoLeaf()
        throws Exception
    {
        byte[] leaf0 = hashFunc.hashLeaf("leaf0".getBytes());
        byte[] leaf1 = hashFunc.hashLeaf("leaf1".getBytes());
        byte[] root = hashFunc.hashNode(leaf0, leaf1);
        List<byte[]> proof = Collections.singletonList(leaf0);
        byte[] computedRoot = MerkleTreePrimitives.evaluateSubtreeInclusionProof(
            1, 0, 2, leaf1, proof, hashFunc);
        isTrue("two-leaf inclusion proof", areEqual(root, computedRoot));
    }

    /**
     * Draft-04 §6.1: signatures in an MTCProof MUST be ordered by cosigner_id
     * (shorter byte strings before longer; same-length lexicographic), and
     * duplicate cosigner_ids MUST be rejected. The constructor must validate
     * this and the parser must reject malformed encodings.
     */
    public void testMTCProofCosignerOrdering()
        throws Exception
    {
        byte[] cosignerShort = binaryTrustAnchorID("32473.1");  // 4 bytes
        byte[] cosignerLong = binaryTrustAnchorID("32473.1.1"); // 5 bytes
        byte[] sigBytes = new byte[64];

        // Correctly ordered: shorter cosigner_id first.
        List<MTCSignature> good = new ArrayList<MTCSignature>();
        good.add(new MTCSignature(cosignerShort, sigBytes));
        good.add(new MTCSignature(cosignerLong, sigBytes));
        org.bouncycastle.cert.plants.MTCProof proof = new org.bouncycastle.cert.plants.MTCProof(
            0L, 2L, hashFunc.hashLeaf("x".getBytes()), good);
        isTrue("ordered MTCProof accepted", proof.getSignatures().size() == 2);

        // Wrong order: longer first must be rejected by the constructor.
        final List<MTCSignature> swapped = new ArrayList<MTCSignature>();
        swapped.add(new MTCSignature(cosignerLong, sigBytes));
        swapped.add(new MTCSignature(cosignerShort, sigBytes));
        testException("not in canonical order", "IllegalArgumentException", new TestExceptionOperation()
        {
            public void operation()
                throws Exception
            {
                new org.bouncycastle.cert.plants.MTCProof(0L, 2L, hashFunc.hashLeaf("x".getBytes()), swapped);
            }
        });

        // Duplicate cosigner_id must also be rejected by the constructor.
        final List<MTCSignature> dup = new ArrayList<MTCSignature>();
        dup.add(new MTCSignature(cosignerShort, sigBytes));
        dup.add(new MTCSignature(cosignerShort, sigBytes));
        testException("Duplicate cosigner_id", "IllegalArgumentException", new TestExceptionOperation()
        {
            public void operation()
                throws Exception
            {
                new org.bouncycastle.cert.plants.MTCProof(0L, 2L, hashFunc.hashLeaf("x".getBytes()), dup);
            }
        });

        // The parser must reject a hand-crafted out-of-order encoding.
        // Encode an MTCProof manually with longer cosigner_id first.
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(new byte[6]);                  // start = 0 (uint48)
        baos.write(0); baos.write(0); baos.write(0); baos.write(0); baos.write(0); baos.write(2); // end = 2

        byte[] inclProofBytes = hashFunc.hashLeaf("x".getBytes());
        baos.write((byte)(inclProofBytes.length >>> 8));
        baos.write((byte)inclProofBytes.length);
        baos.write(inclProofBytes);

        ByteArrayOutputStream sigsBaos = new ByteArrayOutputStream();
        // longer first
        sigsBaos.write((byte)cosignerLong.length);
        sigsBaos.write(cosignerLong);
        sigsBaos.write((byte)0); sigsBaos.write((byte)sigBytes.length);
        sigsBaos.write(sigBytes);
        sigsBaos.write((byte)cosignerShort.length);
        sigsBaos.write(cosignerShort);
        sigsBaos.write((byte)0); sigsBaos.write((byte)sigBytes.length);
        sigsBaos.write(sigBytes);
        byte[] sigsBytes = sigsBaos.toByteArray();
        baos.write((byte)(sigsBytes.length >>> 8));
        baos.write((byte)sigsBytes.length);
        baos.write(sigsBytes);
        final byte[] outOfOrder = baos.toByteArray();
        testException("not in canonical order", "IOException", new TestExceptionOperation()
        {
            public void operation()
                throws Exception
            {
                new org.bouncycastle.cert.plants.MTCProof(outOfOrder);
            }
        });
    }

    // ----- Helpers ----------------------------------------------------------

    /**
     * Encodes a dotted-decimal OID as a binary trust anchor ID (base-128 OID
     * component bytes only, no ASN.1 tag or length).
     */
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

    private static final byte[] SUBTREE_LABEL = new byte[]{
        's', 'u', 'b', 't', 'r', 'e', 'e', '/', 'v', '1', (byte)0x0A, (byte)0x00
    };

    /**
     * Builds a CosignedMessage per Section 5.3.1 of draft-04 for the MTCProof
     * use case (timestamp == 0).
     */
    private byte[] buildSignatureInput(byte[] logId, long start, long end, byte[] subtreeHash, byte[] cosignerId)
        throws IOException
    {
        byte[] cosignerName = asciiName(cosignerId);
        byte[] logOrigin = asciiName(logId);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(SUBTREE_LABEL);                  // 12 bytes
        baos.write((byte)cosignerName.length);
        baos.write(cosignerName);
        writeUint64(baos, 0L);                       // timestamp
        baos.write((byte)logOrigin.length);
        baos.write(logOrigin);
        writeUint64(baos, start);
        writeUint64(baos, end);
        baos.write(subtreeHash);
        return baos.toByteArray();
    }

    /**
     * The ASCII cosigner_name/log_origin form: "oid/1.3.6.1.4.1." + dotted decimal.
     */
    private static byte[] asciiName(byte[] binaryTrustAnchorID)
    {
        String dotted = new ASN1ObjectIdentifier("1.3.6.1.4.1").branch(
            ASN1RelativeOID.fromContents(binaryTrustAnchorID).getId()).getId();
        // dotted is now "1.3.6.1.4.1.<orig>" -- prefix with "oid/" and emit.
        try
        {
            return ("oid/" + dotted).getBytes("US-ASCII");
        }
        catch (java.io.UnsupportedEncodingException e)
        {
            throw new IllegalStateException(e);
        }
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

    private TBSCertificate buildTBSCertificate(
        TBSCertificateLogEntry tbsEntry,
        long serialNumber,
        AlgorithmIdentifier sigAlg,
        SubjectPublicKeyInfo spki)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(serialNumber));  // serialNumber per Section 6.1: (log_number << 48) | index
        v.add(sigAlg);                          // signature
        v.add(tbsEntry.getIssuer());            // issuer
        v.add(tbsEntry.getValidity());          // validity
        v.add(tbsEntry.getSubject());           // subject
        v.add(spki);                            // subjectPublicKeyInfo
        return TBSCertificate.getInstance(new DERSequence(v));
    }

    /**
     * Build the binary trust anchor ID of an issuance log: the CA's binary
     * trust anchor ID followed by base-128(0) and base-128(logNumber).
     */
    private static byte[] binaryLogId(String caDotted, long logNumber)
        throws IOException
    {
        byte[] caId = binaryTrustAnchorID(caDotted);
        byte[] logComponents = binaryTrustAnchorID("0." + logNumber);
        byte[] out = new byte[caId.length + logComponents.length];
        System.arraycopy(caId, 0, out, 0, caId.length);
        System.arraycopy(logComponents, 0, out, caId.length, logComponents.length);
        return out;
    }

    private TBSCertificateLogEntry createDummyTBSCertificateLogEntry()
        throws IOException
    {
        // Section 5.2 (initial experimentation): the issuer name has a single
        // RDN with attribute type id_rdna_trustAnchorID and a UTF8String value
        // containing the dotted-decimal trust anchor ID.
        AttributeTypeAndValue attr = new AttributeTypeAndValue(
            CloudFlareObjectIdentifiers.id_rdna_trustAnchorID,
            new DERUTF8String(LOG_TAID_STRING));
        X500Name issuer = new X500Name(new RDN[]{new RDN(attr)});

        Time notBefore = new Time(new Date());
        Time notAfter = new Time(new Date(System.currentTimeMillis() + 86400000L));
        Validity validity = new Validity(notBefore, notAfter);

        X500Name subject = new X500Name("CN=test");

        AlgorithmIdentifier subjectPublicKeyAlgorithm = new AlgorithmIdentifier(
            new ASN1ObjectIdentifier("1.2.840.10045.2.1"));

        byte[] dummyKey = new byte[10];
        new Random().nextBytes(dummyKey);
        byte[] spkiHash = hashFunc.hashRaw(dummyKey);

        return new TBSCertificateLogEntry(
            new ASN1Integer(0),
            issuer,
            validity,
            subject,
            subjectPublicKeyAlgorithm,
            new DEROctetString(spkiHash),
            null, null, null);
    }

    public String getName()
    {
        return "MerkleTreeCertificates";
    }

    public void performTest()
        throws Exception
    {
        setup();
        testInclusionProofEvaluation();
        testSubtreeConsistencyProofVerification();
        testFindCoveringSubtrees();
        testValidSubtreeCheck();
        testCosignatureVerificationECDSA();
        testCosignatureVerificationEd25519();
        testStandaloneCertificateValidation();
        testLandmarkCertificateValidation();
        testInclusionProofTwoLeaf();
        testMTCProofCosignerOrdering();
    }

    public static void main(String[] args)
    {
        runTest(new MerkleTreeCertificatesTest());
    }
}
