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
import java.util.List;
import java.util.Random;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1RelativeOID;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.plants.MTCObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.MTCCertificationAuthority;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.TBSCertificateLogEntry;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.Validity;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.plants.ListMerkleTreeNodeSource;
import org.bouncycastle.cert.plants.MTCCertAuth;
import org.bouncycastle.cert.plants.MTCContentSigner;
import org.bouncycastle.cert.plants.MTCCosignature;
import org.bouncycastle.cert.plants.MTCCosignedMessage;
import org.bouncycastle.cert.plants.MTCCosignedSubtree;
import org.bouncycastle.cert.plants.MTCCosignerVerifier;
import org.bouncycastle.cert.plants.MTCLog;
import org.bouncycastle.cert.plants.MTCLogEntry;
import org.bouncycastle.cert.plants.MTCLogEntryExtension;
import org.bouncycastle.cert.plants.MTCLogEntryType;
import org.bouncycastle.cert.plants.MTCSignature;
import org.bouncycastle.cert.plants.MTCSignatureVerifierProvider;
import org.bouncycastle.cert.plants.MerkleTreeCertEntry;
import org.bouncycastle.cert.plants.MerkleTreeCertEntryExtension;
import org.bouncycastle.cert.plants.MerkleTreeCertEntryType;
import org.bouncycastle.cert.plants.MerkleTreeCertificateValidator;
import org.bouncycastle.cert.plants.MerkleTreeHash;
import org.bouncycastle.cert.plants.MerkleTreeNodeSource;
import org.bouncycastle.cert.plants.MerkleTreePrimitives;
import org.bouncycastle.cert.plants.TrustAnchorIDs;
import org.bouncycastle.cert.plants.bc.BcMTCCosigner;
import org.bouncycastle.cert.plants.bc.BcMTCCosignerVerifierProvider;
import org.bouncycastle.cert.plants.bc.BcMTCSignatureVerifier;
import org.bouncycastle.cert.plants.bc.BcSha256MerkleTreeHash;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.MLDSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.crypto.signers.MLDSASigner;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Tests for the Merkle Tree Certificates implementation, exercising the
 * primitives, cosignature verification, and full certificate validation paths
 * defined by draft-ietf-plants-merkle-tree-certs-07.
 */
public class MerkleTreeCertificatesTest
    extends SimpleTest
{
    private static final String LOG_TAID_STRING = "32473.1";

    private MerkleTreeHash hashFunc;
    private AsymmetricCipherKeyPair ecdsaKeyPair;
    private AsymmetricCipherKeyPair ed25519KeyPair;
    private byte[] logId;

    public void setup()
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        hashFunc = new BcSha256MerkleTreeHash();

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

        byte[] root = MerkleTreePrimitives.computeMerkleTreeHash(leaves, 0, 8, hashFunc);

        // Inclusion proof for leaf 3 in [0, 8): siblings going up are leaf 2,
        // hash(leaf 0, leaf 1), and hash([4, 6), [6, 8)).
        byte[] leaf2 = leaves.get(2);
        byte[] node01 = hashFunc.hashNode(leaves.get(0), leaves.get(1));
        byte[] node45 = hashFunc.hashNode(leaves.get(4), leaves.get(5));
        byte[] node67 = hashFunc.hashNode(leaves.get(6), leaves.get(7));
        byte[] node47 = hashFunc.hashNode(node45, node67);
        List<byte[]> proof = Arrays.asList(leaf2, node01, node47);

        final byte[] entryHash = leaves.get(3);
        byte[] computedRoot = MerkleTreePrimitives.evaluateSubtreeInclusionProof(
            3, 0, 8, entryHash, proof, hashFunc);
        isTrue("Inclusion proof produces the correct root", areEqual(root, computedRoot));

        final List<byte[]> shortProof = Arrays.asList(leaf2, node01);
        testException(null, "InvalidProofException", new TestExceptionOperation()
        {
            public void operation()
                throws Exception
            {
                MerkleTreePrimitives.evaluateSubtreeInclusionProof(3, 0, 8, entryHash, shortProof, hashFunc);
            }
        });

        final List<byte[]> longProof = Arrays.asList(leaf2, node01, node47, node47);
        testException(null, "InvalidProofException", new TestExceptionOperation()
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
        testException(null, "InvalidProofException", new TestExceptionOperation()
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
        byte[] root14 = MerkleTreePrimitives.computeMerkleTreeHash(leaves, 0, 14, hashFunc);
        byte[] subtreeHash48 = MerkleTreePrimitives.computeMerkleTreeHash(leaves, 4, 8, hashFunc);

        byte[] hash04 = MerkleTreePrimitives.computeMerkleTreeHash(leaves, 0, 4, hashFunc);
        byte[] hash814 = MerkleTreePrimitives.computeMerkleTreeHash(leaves, 8, 14, hashFunc);
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
        byte[] subtreeHash813 = MerkleTreePrimitives.computeMerkleTreeHash(leaves, 8, 13, hashFunc);
        byte[] hashD12 = leaves.get(12);
        byte[] hashD13 = leaves.get(13);
        byte[] hash812 = MerkleTreePrimitives.computeMerkleTreeHash(leaves, 8, 12, hashFunc);
        byte[] hash08 = MerkleTreePrimitives.computeMerkleTreeHash(leaves, 0, 8, hashFunc);
        List<byte[]> proof813 = Arrays.asList(hashD12, hashD13, hash812, hash08);

        isTrue("Consistency proof for partial subtree valid",
            MerkleTreePrimitives.verifySubtreeConsistencyProof(
                8, 13, 14, subtreeHash813, root14, proof813, hashFunc));

        // Subtree [4, 6) inside a tree of size 6. After Section 4.4.3 step 3 the
        // f- and s-paths have already merged at an even node index (fn == sn == 2),
        // so step 7.2.3's "until LSB(sn) is set" shift must still apply with
        // fn == sn -- a guard that stopped shifting once the paths merged
        // rejected this spec-valid proof.
        byte[] root6 = MerkleTreePrimitives.computeMerkleTreeHash(leaves, 0, 6, hashFunc);
        byte[] subtreeHash46 = MerkleTreePrimitives.computeMerkleTreeHash(leaves, 4, 6, hashFunc);
        List<byte[]> proof46 = Collections.singletonList(MerkleTreePrimitives.computeMerkleTreeHash(leaves, 0, 4, hashFunc));

        isTrue("Consistency proof valid when f- and s-paths merge at an even node",
            MerkleTreePrimitives.verifySubtreeConsistencyProof(
                4, 6, 6, subtreeHash46, root6, proof46, hashFunc));

        isTrue("Tampered merged-path consistency proof rejected",
            !MerkleTreePrimitives.verifySubtreeConsistencyProof(
                4, 6, 6, subtreeHash46, root6, Collections.singletonList(badHash), hashFunc));
    }

    public void testProofGeneration()
    {
        List<byte[]> leaves = new ArrayList<byte[]>();
        for (int i = 0; i < 14; i++)
        {
            leaves.add(hashFunc.hashLeaf(("leaf" + i).getBytes()));
        }

        // computeMerkleTreeHash against a hand-built tree of size 8 (RFC 9162 Section 2.1.1).
        byte[] node01 = hashFunc.hashNode(leaves.get(0), leaves.get(1));
        byte[] node23 = hashFunc.hashNode(leaves.get(2), leaves.get(3));
        byte[] node45 = hashFunc.hashNode(leaves.get(4), leaves.get(5));
        byte[] node67 = hashFunc.hashNode(leaves.get(6), leaves.get(7));
        byte[] node03 = hashFunc.hashNode(node01, node23);
        byte[] node47 = hashFunc.hashNode(node45, node67);
        isTrue("MTH of size-8 tree", areEqual(hashFunc.hashNode(node03, node47),
            MerkleTreePrimitives.computeMerkleTreeHash(leaves, 0, 8, hashFunc)));
        isTrue("MTH of a single entry is the entry hash", areEqual(leaves.get(5),
            MerkleTreePrimitives.computeMerkleTreeHash(leaves, 5, 6, hashFunc)));
        // Unbalanced range: k is the largest power of two below the size (4 for [8, 14)).
        isTrue("MTH of unbalanced range", areEqual(
            hashFunc.hashNode(
                MerkleTreePrimitives.computeMerkleTreeHash(leaves, 8, 12, hashFunc),
                hashFunc.hashNode(leaves.get(12), leaves.get(13))),
            MerkleTreePrimitives.computeMerkleTreeHash(leaves, 8, 14, hashFunc)));

        // Inclusion proof for leaf 3 in [0, 8) matches the hand-built one in testInclusionProofEvaluation.
        List<byte[]> incl = MerkleTreePrimitives.generateSubtreeInclusionProof(3, 0, 8, leaves, hashFunc);
        isTrue("Inclusion proof length", incl.size() == 3);
        isTrue("Inclusion proof sibling 0", areEqual(leaves.get(2), incl.get(0)));
        isTrue("Inclusion proof sibling 1", areEqual(node01, incl.get(1)));
        isTrue("Inclusion proof sibling 2", areEqual(node47, incl.get(2)));
        isTrue("Size-one subtree has an empty inclusion proof",
            MerkleTreePrimitives.generateSubtreeInclusionProof(3, 3, 4, leaves, hashFunc).isEmpty());

        // Consistency proofs match the hand-built Figure 7 / Figure 8 proofs in
        // testSubtreeConsistencyProofVerification.
        List<byte[]> cons48 = MerkleTreePrimitives.generateSubtreeConsistencyProof(4, 8, 14, leaves, hashFunc);
        isTrue("Consistency proof [4, 8) in 14", cons48.size() == 2
            && areEqual(MerkleTreePrimitives.computeMerkleTreeHash(leaves, 0, 4, hashFunc), cons48.get(0))
            && areEqual(MerkleTreePrimitives.computeMerkleTreeHash(leaves, 8, 14, hashFunc), cons48.get(1)));
        List<byte[]> cons813 = MerkleTreePrimitives.generateSubtreeConsistencyProof(8, 13, 14, leaves, hashFunc);
        isTrue("Consistency proof [8, 13) in 14", cons813.size() == 4
            && areEqual(leaves.get(12), cons813.get(0))
            && areEqual(leaves.get(13), cons813.get(1))
            && areEqual(MerkleTreePrimitives.computeMerkleTreeHash(leaves, 8, 12, hashFunc), cons813.get(2))
            && areEqual(MerkleTreePrimitives.computeMerkleTreeHash(leaves, 0, 8, hashFunc), cons813.get(3)));
        isTrue("Whole tree has an empty consistency proof",
            MerkleTreePrimitives.generateSubtreeConsistencyProof(0, 14, 14, leaves, hashFunc).isEmpty());

        // Generate-then-verify round trips over every valid subtree of every tree size up to 14,
        // and every entry of every subtree.
        byte[] badHash = hashFunc.hashLeaf("bad".getBytes());
        for (int n = 1; n <= 14; n++)
        {
            byte[] root = MerkleTreePrimitives.computeMerkleTreeHash(leaves, 0, n, hashFunc);
            for (int start = 0; start < n; start++)
            {
                for (int end = start + 1; end <= n; end++)
                {
                    if (!MerkleTreePrimitives.isValidSubtree(start, end))
                    {
                        continue;
                    }
                    byte[] subtreeHash = MerkleTreePrimitives.computeMerkleTreeHash(leaves, start, end, hashFunc);

                    List<byte[]> cons = MerkleTreePrimitives.generateSubtreeConsistencyProof(
                        start, end, n, leaves, hashFunc);
                    isTrue("Consistency round trip [" + start + ", " + end + ") in " + n,
                        MerkleTreePrimitives.verifySubtreeConsistencyProof(
                            start, end, n, subtreeHash, root, cons, hashFunc));
                    if (!cons.isEmpty())
                    {
                        List<byte[]> tampered = new ArrayList<byte[]>(cons);
                        tampered.set(tampered.size() - 1, badHash);
                        isTrue("Tampered consistency proof [" + start + ", " + end + ") in " + n,
                            !MerkleTreePrimitives.verifySubtreeConsistencyProof(
                                start, end, n, subtreeHash, root, tampered, hashFunc));
                    }

                    for (int index = start; index < end; index++)
                    {
                        List<byte[]> proof = MerkleTreePrimitives.generateSubtreeInclusionProof(
                            index, start, end, leaves, hashFunc);
                        isTrue("Inclusion round trip " + index + " in [" + start + ", " + end + ")",
                            MerkleTreePrimitives.verifySubtreeInclusionProof(
                                index, start, end, leaves.get(index), subtreeHash, proof, hashFunc));
                        if (start == 0 && end == n)
                        {
                            // Section 4.4.1: SUBTREE_PROOF(start, start + 1, D_n) = PATH(start, D_n).
                            List<byte[]> single = MerkleTreePrimitives.generateSubtreeConsistencyProof(
                                index, index + 1, n, leaves, hashFunc);
                            isTrue("Size-one consistency proof equals inclusion proof for " + index + " in " + n,
                                single.size() == proof.size());
                            for (int i = 0; i != proof.size(); i++)
                            {
                                isTrue("Size-one consistency proof element " + i,
                                    areEqual(proof.get(i), single.get(i)));
                            }
                        }
                    }
                }
            }
        }

        // Argument checking.
        final List<byte[]> fLeaves = leaves;
        testException("Invalid subtree interval or index", "IllegalArgumentException", new TestExceptionOperation()
        {
            public void operation()
            {
                MerkleTreePrimitives.generateSubtreeInclusionProof(3, 3, 5, fLeaves, hashFunc); // not a subtree
            }
        });
        testException("Invalid subtree interval or index", "IllegalArgumentException", new TestExceptionOperation()
        {
            public void operation()
            {
                MerkleTreePrimitives.generateSubtreeInclusionProof(8, 0, 8, fLeaves, hashFunc); // index outside
            }
        });
        testException("Invalid subtree interval or tree size", "IllegalArgumentException", new TestExceptionOperation()
        {
            public void operation()
            {
                MerkleTreePrimitives.generateSubtreeConsistencyProof(4, 8, 6, fLeaves, hashFunc); // end > n
            }
        });
        testException("is invalid or not covered by", "IllegalArgumentException", new TestExceptionOperation()
        {
            public void operation()
            {
                MerkleTreePrimitives.generateSubtreeConsistencyProof(4, 8, 16, fLeaves, hashFunc); // n > entries
            }
        });
        testException("is invalid or not covered by", "IllegalArgumentException", new TestExceptionOperation()
        {
            public void operation()
            {
                MerkleTreePrimitives.computeMerkleTreeHash(fLeaves, 6, 5, hashFunc);
            }
        });

        // The empty subtree [5, 5): MTH is HASH(""), its consistency proof with any
        // tree is empty, and verification accepts exactly that pair (Section 4.4.3 step 2).
        byte[] emptyHash = hashFunc.hashRaw(new byte[0]);
        isTrue("MTH of empty range is HASH(\"\")",
            areEqual(emptyHash, MerkleTreePrimitives.computeMerkleTreeHash(fLeaves, 5, 5, hashFunc)));
        isTrue("MTH of empty range from a node source",
            areEqual(emptyHash, new ListMerkleTreeNodeSource(fLeaves, hashFunc).getFullSubtreeHash(5, 5)));
        List<byte[]> emptyProof = MerkleTreePrimitives.generateSubtreeConsistencyProof(5, 5, 8, fLeaves, hashFunc);
        isTrue("empty subtree has empty consistency proof", emptyProof.isEmpty());
        byte[] root8 = MerkleTreePrimitives.computeMerkleTreeHash(fLeaves, 0, 8, hashFunc);
        isTrue("empty subtree consistency proof verifies", MerkleTreePrimitives.verifySubtreeConsistencyProof(
            5, 5, 8, emptyHash, root8, emptyProof, hashFunc));
        isTrue("empty subtree rejects a non-empty proof", !MerkleTreePrimitives.verifySubtreeConsistencyProof(
            5, 5, 8, emptyHash, root8, Collections.singletonList(root8), hashFunc));
        isTrue("empty subtree rejects a wrong hash", !MerkleTreePrimitives.verifySubtreeConsistencyProof(
            5, 5, 8, root8, root8, emptyProof, hashFunc));
        isTrue("empty subtree past the tree end is rejected", !MerkleTreePrimitives.verifySubtreeConsistencyProof(
            9, 9, 8, emptyHash, root8, emptyProof, hashFunc));
    }

    public void testNodeSourceProofGeneration()
    {
        final List<byte[]> leaves = new ArrayList<byte[]>();
        for (int i = 0; i < 14; i++)
        {
            leaves.add(hashFunc.hashLeaf(("leaf" + i).getBytes()));
        }

        isTrue("isFullSubtree [0, 8)", MerkleTreePrimitives.isFullSubtree(0, 8));
        isTrue("isFullSubtree [8, 12)", MerkleTreePrimitives.isFullSubtree(8, 12));
        isTrue("isFullSubtree [5, 6)", MerkleTreePrimitives.isFullSubtree(5, 6));
        isTrue("isFullSubtree [4, 6)", MerkleTreePrimitives.isFullSubtree(4, 6));
        isTrue("!isFullSubtree [2, 6)", !MerkleTreePrimitives.isFullSubtree(2, 6));
        isTrue("!isFullSubtree [0, 6)", !MerkleTreePrimitives.isFullSubtree(0, 6));
        isTrue("!isFullSubtree [3, 3)", !MerkleTreePrimitives.isFullSubtree(3, 3));

        // A stand-in for a storage-backed log: only the full subtrees a log stores are
        // available, requests for anything else fail, and requests are counted.
        final java.util.Map<String, byte[]> stored = new java.util.HashMap<String, byte[]>();
        for (int size = 1; size <= 8; size <<= 1)
        {
            for (int start = 0; start + size <= 14; start += size)
            {
                stored.put(start + ":" + (start + size),
                    MerkleTreePrimitives.computeMerkleTreeHash(leaves, start, start + size, hashFunc));
            }
        }
        final int[] requests = new int[1];
        MerkleTreeNodeSource log = new MerkleTreeNodeSource()
        {
            public byte[] getFullSubtreeHash(long start, long end)
            {
                requests[0]++;
                if (!MerkleTreePrimitives.isFullSubtree(start, end))
                {
                    fail("non-full subtree requested: [" + start + ", " + end + ")");
                }
                byte[] node = stored.get(start + ":" + end);
                if (node == null)
                {
                    throw new IllegalArgumentException("not stored: [" + start + ", " + end + ")");
                }
                return node;
            }
        };

        // Every hash and proof from the storage-backed source equals the in-memory one.
        for (int n = 1; n <= 14; n++)
        {
            isTrue("root " + n, areEqual(
                MerkleTreePrimitives.computeMerkleTreeHash(leaves, 0, n, hashFunc),
                MerkleTreePrimitives.computeMerkleTreeHash(log, 0, n, hashFunc)));
            for (int start = 0; start < n; start++)
            {
                for (int end = start + 1; end <= n; end++)
                {
                    isTrue("range [" + start + ", " + end + ")", areEqual(
                        MerkleTreePrimitives.computeMerkleTreeHash(leaves, start, end, hashFunc),
                        MerkleTreePrimitives.computeMerkleTreeHash(log, start, end, hashFunc)));
                    if (!MerkleTreePrimitives.isValidSubtree(start, end))
                    {
                        continue;
                    }
                    isTrue("consistency [" + start + ", " + end + ") in " + n, sameHashes(
                        MerkleTreePrimitives.generateSubtreeConsistencyProof(start, end, n, leaves, hashFunc),
                        MerkleTreePrimitives.generateSubtreeConsistencyProof(start, end, n, log, hashFunc)));
                    for (int index = start; index < end; index++)
                    {
                        isTrue("inclusion " + index + " in [" + start + ", " + end + ")", sameHashes(
                            MerkleTreePrimitives.generateSubtreeInclusionProof(index, start, end, leaves, hashFunc),
                            MerkleTreePrimitives.generateSubtreeInclusionProof(index, start, end, log, hashFunc)));
                    }
                }
            }
        }

        // A proof over [8, 13) in 14 needs the nodes 12, 13, [8, 12) and [0, 8): four requests,
        // one per proof element, none of them below a stored node.
        requests[0] = 0;
        MerkleTreePrimitives.generateSubtreeConsistencyProof(8, 13, 14, log, hashFunc);
        isTrue("consistency proof made " + requests[0] + " requests", requests[0] == 4);

        // The tree size is the caller's statement; a node beyond what the source holds
        // surfaces as the source's own exception.
        testException("not stored", "IllegalArgumentException", new TestExceptionOperation()
        {
            public void operation()
            {
                MerkleTreePrimitives.generateSubtreeConsistencyProof(8, 12, 16, log, hashFunc);
            }
        });
        // A null from the source is rejected rather than passed into the hash.
        testException("returned no hash", "IllegalArgumentException", new TestExceptionOperation()
        {
            public void operation()
            {
                MerkleTreePrimitives.computeMerkleTreeHash(new MerkleTreeNodeSource()
                {
                    public byte[] getFullSubtreeHash(long start, long end)
                    {
                        return null;
                    }
                }, 0, 4, hashFunc);
            }
        });
        // The empty range is HASH("") and is answered without consulting the source.
        int requestsBefore = requests[0];
        isTrue("MTH of empty range from a node source is HASH(\"\")", areEqual(
            hashFunc.hashRaw(new byte[0]), MerkleTreePrimitives.computeMerkleTreeHash(log, 4, 4, hashFunc)));
        isTrue("empty range made no request", requests[0] == requestsBefore);
        testException("is invalid", "IllegalArgumentException", new TestExceptionOperation()
        {
            public void operation()
            {
                MerkleTreePrimitives.computeMerkleTreeHash(log, 5, 4, hashFunc);
            }
        });
        testException("nodes must not be null", "IllegalArgumentException", new TestExceptionOperation()
        {
            public void operation()
            {
                MerkleTreePrimitives.generateSubtreeInclusionProof(0, 0, 4, (MerkleTreeNodeSource)null, hashFunc);
            }
        });

        // The list adapter is what the list overloads use, and checks its bounds.
        final ListMerkleTreeNodeSource adapted = new ListMerkleTreeNodeSource(leaves, hashFunc);
        isTrue("adapter size", adapted.size() == 14);
        isTrue("adapter node", areEqual(stored.get("8:12"), adapted.getFullSubtreeHash(8, 12)));
        testException("not covered by", "IllegalArgumentException", new TestExceptionOperation()
        {
            public void operation()
            {
                adapted.getFullSubtreeHash(8, 16);
            }
        });

        // The adapter keeps the nodes it computes and reads the list in place, so a
        // source built over a growing log answers for the appended entries too, with
        // the same results as a source built after the fact, and the hashes it hands
        // out are copies that a caller cannot corrupt the cache through.
        List<byte[]> growing = new ArrayList<byte[]>(leaves.subList(0, 9));
        ListMerkleTreeNodeSource source = new ListMerkleTreeNodeSource(growing, hashFunc);
        byte[] root9 = MerkleTreePrimitives.computeMerkleTreeHash(source, 0, 9, hashFunc);
        isTrue("root of 9 from a growing source", areEqual(
            MerkleTreePrimitives.computeMerkleTreeHash(leaves, 0, 9, hashFunc), root9));
        root9[0] ^= 0x01;
        isTrue("a returned node is a copy", areEqual(
            MerkleTreePrimitives.computeMerkleTreeHash(leaves, 0, 9, hashFunc),
            MerkleTreePrimitives.computeMerkleTreeHash(source, 0, 9, hashFunc)));
        growing.addAll(leaves.subList(9, 14));
        isTrue("source size follows the list", source.size() == 14);
        isTrue("root of 14 after appending", areEqual(
            MerkleTreePrimitives.computeMerkleTreeHash(leaves, 0, 14, hashFunc),
            MerkleTreePrimitives.computeMerkleTreeHash(source, 0, 14, hashFunc)));
        isTrue("consistency proof after appending", sameHashes(
            MerkleTreePrimitives.generateSubtreeConsistencyProof(8, 13, 14, leaves, hashFunc),
            MerkleTreePrimitives.generateSubtreeConsistencyProof(8, 13, 14, source, hashFunc)));
        for (int index = 0; index < 14; index++)
        {
            isTrue("inclusion proof " + index + " after appending", sameHashes(
                MerkleTreePrimitives.generateSubtreeInclusionProof(index, 0, 14, leaves, hashFunc),
                MerkleTreePrimitives.generateSubtreeInclusionProof(index, 0, 14, source, hashFunc)));
        }
    }

    private boolean sameHashes(List<byte[]> a, List<byte[]> b)
    {
        if (a.size() != b.size())
        {
            return false;
        }
        for (int i = 0; i < a.size(); i++)
        {
            if (!areEqual(a.get(i), b.get(i)))
            {
                return false;
            }
        }
        return true;
    }

    public void testFindCoveringSubtrees()
    {
        List<long[]> subtrees = MerkleTreePrimitives.findCoveringSubtrees(5, 13);
        isEquals(2, subtrees.size());
        isEquals(4, subtrees.get(0)[0]);
        isEquals(8, subtrees.get(0)[1]);
        isEquals(8, subtrees.get(1)[0]);
        isEquals(13, subtrees.get(1)[1]);

        // Section 4.5.1 step 1: an interval of at most one entry is covered by
        // itself and the empty subtree [end, end), so the result is always two.
        subtrees = MerkleTreePrimitives.findCoveringSubtrees(7, 8);
        isEquals(2, subtrees.size());
        isEquals(7, subtrees.get(0)[0]);
        isEquals(8, subtrees.get(0)[1]);
        isEquals(8, subtrees.get(1)[0]);
        isEquals(8, subtrees.get(1)[1]);

        subtrees = MerkleTreePrimitives.findCoveringSubtrees(9, 9);
        isEquals(2, subtrees.size());
        isEquals(9, subtrees.get(0)[0]);
        isEquals(9, subtrees.get(0)[1]);
        isEquals(9, subtrees.get(1)[0]);
        isEquals(9, subtrees.get(1)[1]);

        // Appendix C.2.4 large-tree samples.
        subtrees = MerkleTreePrimitives.findCoveringSubtrees(0x0L, 0x800000000000L);
        isEquals(0x0L, subtrees.get(0)[0]);
        isEquals(0x400000000000L, subtrees.get(0)[1]);
        isEquals(0x400000000000L, subtrees.get(1)[0]);
        isEquals(0x800000000000L, subtrees.get(1)[1]);

        subtrees = MerkleTreePrimitives.findCoveringSubtrees(0x500000000000L, 0xd00000000000L);
        isEquals(0x400000000000L, subtrees.get(0)[0]);
        isEquals(0x800000000000L, subtrees.get(0)[1]);
        isEquals(0x800000000000L, subtrees.get(1)[0]);
        isEquals(0xd00000000000L, subtrees.get(1)[1]);

        subtrees = MerkleTreePrimitives.findCoveringSubtrees(0x7fffffffffffL, 0x800000000001L);
        isEquals(0x7fffffffffffL, subtrees.get(0)[0]);
        isEquals(0x800000000000L, subtrees.get(0)[1]);
        isEquals(0x800000000000L, subtrees.get(1)[0]);
        isEquals(0x800000000001L, subtrees.get(1)[1]);

        testException("start must not exceed end", "IllegalArgumentException", new TestExceptionOperation()
        {
            public void operation()
                throws Exception
            {
                MerkleTreePrimitives.findCoveringSubtrees(9, 8);
            }
        });

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

        // Degenerate ranges: [x, x) is valid for every x (BIT_CEIL(0) is 1).
        isTrue("end == start is valid", MerkleTreePrimitives.isValidSubtree(5, 5));
        isTrue("[0, 0) is valid", MerkleTreePrimitives.isValidSubtree(0, 0));
        isTrue("end < start is invalid", !MerkleTreePrimitives.isValidSubtree(10, 5));
        isTrue("negative start is invalid", !MerkleTreePrimitives.isValidSubtree(-1, 5));

        // Appendix C.2.1 large-tree cases, up to the 2^63 - 1 that a long can hold.
        isTrue("[0, 2^47 + 1) is valid", MerkleTreePrimitives.isValidSubtree(0, (1L << 47) + 1));
        isTrue("[0, 2^48 - 1) is valid", MerkleTreePrimitives.isValidSubtree(0, (1L << 48) - 1));
        isTrue("[0, 2^62 + 1) is valid", MerkleTreePrimitives.isValidSubtree(0, (1L << 62) + 1));
        isTrue("[0, 2^63 - 1) is valid", MerkleTreePrimitives.isValidSubtree(0, Long.MAX_VALUE));
        isTrue("[2^46, 2^47 + 1) is invalid", !MerkleTreePrimitives.isValidSubtree(1L << 46, (1L << 47) + 1));
        isTrue("[2^46, 2^48 - 1) is invalid", !MerkleTreePrimitives.isValidSubtree(1L << 46, (1L << 48) - 1));
        isTrue("[2^61, 2^62 + 1) is invalid", !MerkleTreePrimitives.isValidSubtree(1L << 61, (1L << 62) + 1));
        isTrue("[2^61, 2^63 - 1) is invalid", !MerkleTreePrimitives.isValidSubtree(1L << 61, Long.MAX_VALUE));
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

        byte[] cosignedMessage = MTCCosignedSubtree.encode(logId, start, end, subtreeHash, cosignerId);
        BcMTCSignatureVerifier ecdsaVerifier = new BcMTCSignatureVerifier(
            "ECDSA-P256-SHA256", ecdsaKeyPair.getPublic());

        isTrue("ECDSA cosignature verifies", ecdsaVerifier.verify(cosignedMessage, signature));
        isTrue("bound algorithm surfaced", "ECDSA-P256-SHA256".equals(ecdsaVerifier.getAlgorithm()));

        signature[0] ^= 0x01;
        isTrue("Tampered ECDSA signature rejected", !ecdsaVerifier.verify(cosignedMessage, signature));
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

        byte[] cosignedMessage = MTCCosignedSubtree.encode(logId, start, end, subtreeHash, cosignerId);
        BcMTCSignatureVerifier ed25519Verifier = new BcMTCSignatureVerifier(
            "Ed25519", ed25519KeyPair.getPublic());

        isTrue("Ed25519 cosignature verifies", ed25519Verifier.verify(cosignedMessage, signature));

        signature[0] ^= 0x01;
        isTrue("Tampered Ed25519 signature rejected", !ed25519Verifier.verify(cosignedMessage, signature));
    }

    public void testCosignatureVerificationEcdsaP384()
        throws Exception
    {
        ECKeyPairGenerator ecGen = new ECKeyPairGenerator();
        ECNamedDomainParameters ecParams = new ECNamedDomainParameters(
            new ASN1ObjectIdentifier("1.3.132.0.34"),
            SECNamedCurves.getByName("secp384r1"));
        ecGen.init(new ECKeyGenerationParameters(ecParams, new SecureRandom()));
        AsymmetricCipherKeyPair p384KeyPair = ecGen.generateKeyPair();

        long start = 100;
        long end = 200;
        byte[] subtreeHash = hashFunc.hashLeaf("dummy subtree".getBytes());
        byte[] cosignerId = binaryTrustAnchorID("32473.4");

        byte[] signedData = buildSignatureInput(logId, start, end, subtreeHash, cosignerId);

        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA384Digest()));
        signer.init(true, p384KeyPair.getPrivate());

        SHA384Digest digest = new SHA384Digest();
        byte[] hash = new byte[digest.getDigestSize()];
        digest.update(signedData, 0, signedData.length);
        digest.doFinal(hash, 0);

        BigInteger[] rs = signer.generateSignature(hash);
        byte[] r = BigIntegers.asUnsignedByteArray(48, rs[0]);
        byte[] s = BigIntegers.asUnsignedByteArray(48, rs[1]);
        byte[] signature = new byte[96];
        System.arraycopy(r, 0, signature, 0, 48);
        System.arraycopy(s, 0, signature, 48, 48);

        byte[] cosignedMessage = MTCCosignedSubtree.encode(logId, start, end, subtreeHash, cosignerId);
        BcMTCSignatureVerifier verifier = new BcMTCSignatureVerifier(
            "ECDSA-P384-SHA384", p384KeyPair.getPublic());

        isTrue("ECDSA-P384 cosignature verifies", verifier.verify(cosignedMessage, signature));

        signature[0] ^= 0x01;
        isTrue("Tampered ECDSA-P384 signature rejected", !verifier.verify(cosignedMessage, signature));
    }

    public void testCosignatureVerificationMlDsa44()
        throws Exception
    {
        verifyMlDsaCosignature(MLDSAParameters.ml_dsa_44, "ML-DSA-44", "32473.5");
    }

    public void testCosignatureVerificationMlDsa65()
        throws Exception
    {
        verifyMlDsaCosignature(MLDSAParameters.ml_dsa_65, "ML-DSA-65", "32473.6");
    }

    public void testCosignatureVerificationMlDsa87()
        throws Exception
    {
        verifyMlDsaCosignature(MLDSAParameters.ml_dsa_87, "ML-DSA-87", "32473.7");
    }

    private void verifyMlDsaCosignature(MLDSAParameters params, String alg, String cosignerIdDotted)
        throws Exception
    {
        SecureRandom random = new SecureRandom();
        MLDSAKeyPairGenerator gen = new MLDSAKeyPairGenerator();
        gen.init(new MLDSAKeyGenerationParameters(random, params));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();

        long start = 100;
        long end = 200;
        byte[] subtreeHash = hashFunc.hashLeaf("dummy subtree".getBytes());
        byte[] cosignerId = binaryTrustAnchorID(cosignerIdDotted);

        byte[] signedData = buildSignatureInput(logId, start, end, subtreeHash, cosignerId);

        MLDSASigner signer = new MLDSASigner();
        signer.init(true, kp.getPrivate());
        signer.update(signedData, 0, signedData.length);
        byte[] signature = signer.generateSignature();

        byte[] cosignedMessage = MTCCosignedSubtree.encode(logId, start, end, subtreeHash, cosignerId);
        BcMTCSignatureVerifier verifier = new BcMTCSignatureVerifier(alg, kp.getPublic());

        isTrue(alg + " cosignature verifies", verifier.verify(cosignedMessage, signature));

        signature[signature.length / 2] ^= 0x01;
        isTrue("Tampered " + alg + " signature rejected", !verifier.verify(cosignedMessage, signature));
    }

    public void testMTCSignatureVerifierProviderManualMode()
        throws Exception
    {
        // Build a CosignedMessage and sign it directly with Ed25519, then drive
        // verification through the ContentVerifier exposed by the provider's
        // manual-mode constructor.
        long start = 100;
        long end = 200;
        byte[] subtreeHash = hashFunc.hashLeaf("dummy subtree".getBytes());
        byte[] cosignerId = binaryTrustAnchorID("32473.8");

        byte[] signedData = buildSignatureInput(logId, start, end, subtreeHash, cosignerId);
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, ed25519KeyPair.getPrivate());
        signer.update(signedData, 0, signedData.length);
        byte[] signature = signer.generateSignature();

        byte[] cosignedMessage = MTCCosignedSubtree.encode(logId, start, end, subtreeHash, cosignerId);

        MTCCosignerVerifier cosignerVerifier =
            BcMTCCosignerVerifierProvider.singleCosigner(cosignerId, ed25519KeyPair.getPublic())
                .get(cosignerId);
        MTCSignatureVerifierProvider provider = new MTCSignatureVerifierProvider(cosignerVerifier);
        AlgorithmIdentifier algId = new AlgorithmIdentifier(MTCObjectIdentifiers.id_alg_mtcProof);

        ContentVerifier cv = provider.get(algId);
        java.io.OutputStream sOut = cv.getOutputStream();
        sOut.write(cosignedMessage);
        sOut.close();
        isTrue("manual-mode cosignature verifies", cv.verify(signature));

        signature[0] ^= 0x01;
        cv = provider.get(algId);
        sOut = cv.getOutputStream();
        sOut.write(cosignedMessage);
        sOut.close();
        isTrue("manual-mode tampered signature rejected", !cv.verify(signature));
    }

    public void testMTCSignatureVerifierProviderCertificateMode()
        throws Exception
    {
        // Issue an MTC cert end-to-end using the high-level builder so we have
        // a realistic certificate to validate via X509CertificateHolder.isSignatureValid.
        SecureRandom random = new SecureRandom();
        Ed25519KeyPairGenerator caGen = new Ed25519KeyPairGenerator();
        caGen.init(new Ed25519KeyGenerationParameters(random));
        AsymmetricCipherKeyPair certCaKp = caGen.generateKeyPair();

        Ed25519KeyPairGenerator eeGen = new Ed25519KeyPairGenerator();
        eeGen.init(new Ed25519KeyGenerationParameters(random));
        AsymmetricCipherKeyPair eeKp = eeGen.generateKeyPair();
        SubjectPublicKeyInfo eeSpki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(eeKp.getPublic());

        MTCCertAuth ca = new MTCCertAuth(
            LOG_TAID_STRING,
            new BcSha256MerkleTreeHash(),
            MTCObjectIdentifiers.id_alg_mtcProof);
        MTCLog log = new MTCLog(ca, 1L, 0L, 2L);
        byte[] siblingHash = hashFunc.hashLeaf("sibling".getBytes());

        ContentSigner mtcSigner = new MTCContentSigner(
            log, siblingHash,
            new BcMTCCosigner(ca.getCaId(), certCaKp.getPrivate()));

        long now = System.currentTimeMillis();
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
            ca.issuerName(), ca.certSerial(log, 0L),
            new Date(now), new Date(now + 24L * 60 * 60 * 1000),
            new org.bouncycastle.asn1.x500.X500Name("CN=mtc-test-ee"), eeSpki);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        X509CertificateHolder cert = builder.build(mtcSigner);

        MTCCosignerVerifier cosignerVerifier =
            BcMTCCosignerVerifierProvider.singleCosigner(ca.getCaId(), certCaKp.getPublic())
                .get(ca.getCaId());
        ContentVerifierProvider provider = new MTCSignatureVerifierProvider(ca, cosignerVerifier);

        isTrue("certificate-mode isSignatureValid passes", cert.isSignatureValid(provider));

        // Flip a bit in the encoded cert — lands inside the cosigner signature
        // in the MTCProof — and confirm the adapter rejects it.
        byte[] tamperedBytes = cert.getEncoded();
        tamperedBytes[tamperedBytes.length - 1] ^= 0x01;
        X509CertificateHolder tamperedCert = new X509CertificateHolder(tamperedBytes);
        isTrue("certificate-mode rejects tampered cert", !tamperedCert.isSignatureValid(provider));

        // A cosignature attributed to a foreign cosigner_id must be ignored
        // (Section 7.2 step 12) even when it cryptographically verifies under
        // the wrapped key — here the CA's key signs under another identity.
        byte[] foreignId = binaryTrustAnchorID("32473.99");
        ContentSigner foreignSigner = new MTCContentSigner(
            log, siblingHash,
            new BcMTCCosigner(foreignId, certCaKp.getPrivate()));
        X509v3CertificateBuilder foreignBuilder = new X509v3CertificateBuilder(
            ca.issuerName(), ca.certSerial(log, 0L),
            new Date(now), new Date(now + 24L * 60 * 60 * 1000),
            new org.bouncycastle.asn1.x500.X500Name("CN=mtc-test-ee"), eeSpki);
        foreignBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        X509CertificateHolder foreignCert = foreignBuilder.build(foreignSigner);
        isTrue("certificate-mode ignores cosignature with foreign cosigner_id",
            !foreignCert.isSignatureValid(provider));
    }

    /**
     * The certificate-mode adapter follows Section 7.2 for any subtree shape:
     * the entry index comes from the serial and the inclusion proof is
     * evaluated in full, so an EE at index 2 of the four-entry subtree [0, 4)
     * (a two-hash proof) verifies through isSignatureValid exactly as it does
     * through the validator, and the same proof presented under a serial that
     * names another index does not.
     */
    public void testCertificateModeGeneralSubtree()
        throws Exception
    {
        SecureRandom random = new SecureRandom();
        Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
        gen.init(new Ed25519KeyGenerationParameters(random));
        AsymmetricCipherKeyPair caKp = gen.generateKeyPair();
        AsymmetricCipherKeyPair eeKp = gen.generateKeyPair();
        SubjectPublicKeyInfo eeSpki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(eeKp.getPublic());

        MTCCertAuth ca = new MTCCertAuth(
            LOG_TAID_STRING,
            new BcSha256MerkleTreeHash(),
            MTCObjectIdentifiers.id_alg_mtcProof);
        MTCLog log = new MTCLog(ca, 1L, 0L, 4L);
        long index = 2L;

        // The proof for index 2 in [0, 4) is {leaf 3, MTH([0, 2))}; it does not
        // depend on entry 2 itself, so placeholder entries suffice to build it.
        List<byte[]> entryHashes = new ArrayList<byte[]>();
        for (int i = 0; i < 4; i++)
        {
            entryHashes.add(hashFunc.hashLeaf(("entry-" + i).getBytes()));
        }
        List<byte[]> proofHashes = MerkleTreePrimitives.generateSubtreeInclusionProof(
            index, 0L, 4L, entryHashes, hashFunc);
        isTrue("two-hash inclusion proof", proofHashes.size() == 2);
        ByteArrayOutputStream proofOut = new ByteArrayOutputStream();
        for (int i = 0; i < proofHashes.size(); i++)
        {
            proofOut.write((byte[])proofHashes.get(i));
        }
        byte[] inclusionProof = proofOut.toByteArray();

        ContentSigner mtcSigner = new MTCContentSigner(
            log, inclusionProof, new BcMTCCosigner(ca.getCaId(), caKp.getPrivate()));

        long now = System.currentTimeMillis();
        X509CertificateHolder cert = new X509v3CertificateBuilder(
            ca.issuerName(), ca.certSerial(log, index),
            new Date(now), new Date(now + 24L * 60 * 60 * 1000),
            new X500Name("CN=mtc-test-ee"), eeSpki).build(mtcSigner);

        ContentVerifierProvider provider = new MTCSignatureVerifierProvider(ca,
            BcMTCCosignerVerifierProvider.singleCosigner(ca.getCaId(), caKp.getPublic()).get(ca.getCaId()));
        isTrue("certificate-mode verifies a two-level inclusion proof", cert.isSignatureValid(provider));

        isTrue("validator agrees", MerkleTreeCertificateValidator.validateCertificate(cert,
            new MerkleTreeCertificateValidator.ValidationParams(
                BcMTCCosignerVerifierProvider.singleCosigner(ca.getCaId(), caKp.getPublic()),
                hashFunc, 1, null)));

        // Replay the same MTCProof under a serial naming index 3: the recomputed
        // subtree hash is not the one the cosigner signed.
        final byte[] proofBytes = cert.getSignature();
        ContentSigner replay = new ContentSigner()
        {
            public AlgorithmIdentifier getAlgorithmIdentifier()
            {
                return new AlgorithmIdentifier(MTCObjectIdentifiers.id_alg_mtcProof);
            }

            public java.io.OutputStream getOutputStream()
            {
                return new ByteArrayOutputStream();
            }

            public byte[] getSignature()
            {
                return proofBytes;
            }
        };
        X509CertificateHolder wrongIndex = new X509v3CertificateBuilder(
            ca.issuerName(), ca.certSerial(log, 3L),
            new Date(now), new Date(now + 24L * 60 * 60 * 1000),
            new X500Name("CN=mtc-test-ee"), eeSpki).build(replay);
        isTrue("serial naming another index is rejected", !wrongIndex.isSignatureValid(provider));
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
        final long serial = (logNumber << 48) | index;  // Section 6.2
        long start = 42;
        long end = 44;
        // Construct the log ID by appending OID components 0 and logNumber to
        // the CA ID, matching what the validator will compute.
        byte[] cosignedLogId = binaryLogId(LOG_TAID_STRING, logNumber);

        AlgorithmIdentifier sigAlg = new AlgorithmIdentifier(MTCObjectIdentifiers.id_alg_mtcProof);
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

        List<MTCCosignature> sigs = Collections.singletonList(new MTCCosignature(cosignerId, signature));
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
                hashFunc, Collections.<MerkleTreeCertificateValidator.TrustedSubtree>emptyList(),
                Collections.<MerkleTreeCertificateValidator.RevokedRange>emptyList(),
                1
            );

        isTrue("Standalone certificate validates", MerkleTreeCertificateValidator.validateCertificate(cert, params));

        // Tightening the policy beyond what the certificate carries must fail.
        final MerkleTreeCertificateValidator.ValidationParams strict =
            new MerkleTreeCertificateValidator.ValidationParams(
                cosigners,
                hashFunc, Collections.<MerkleTreeCertificateValidator.TrustedSubtree>emptyList(),
                Collections.<MerkleTreeCertificateValidator.RevokedRange>emptyList(),
                2
            );
        testException("Insufficient valid cosignatures", "SecurityException", new TestExceptionOperation()
        {
            public void operation()
                throws Exception
            {
                MerkleTreeCertificateValidator.validateCertificate(cert, strict);
            }
        });

        // Revoking a range containing the serial must fail validation. The
        // range is over full serials (Section 7.5), so it is log-scoped.
        final MerkleTreeCertificateValidator.ValidationParams revokedParams =
            new MerkleTreeCertificateValidator.ValidationParams(
                cosigners,
                hashFunc, Collections.<MerkleTreeCertificateValidator.TrustedSubtree>emptyList(),
                Collections.singletonList(
                    MerkleTreeCertificateValidator.RevokedRange.ofIndices(logNumber, index, index + 1)),
                1
            );
        testException("revoked", "SecurityException", new TestExceptionOperation()
        {
            public void operation()
                throws Exception
            {
                MerkleTreeCertificateValidator.validateCertificate(cert, revokedParams);
            }
        });

        // Ranges are over full serials, so revoking all of log 2 must leave
        // this log-1 certificate valid, while revoking all of log 1 must not.
        final MerkleTreeCertificateValidator.ValidationParams otherLogRevoked =
            new MerkleTreeCertificateValidator.ValidationParams(
                cosigners,
                hashFunc, Collections.<MerkleTreeCertificateValidator.TrustedSubtree>emptyList(),
                Collections.singletonList(MerkleTreeCertificateValidator.RevokedRange.ofLog(2)),
                1
            );
        isTrue("Revoking another log leaves this certificate valid",
            MerkleTreeCertificateValidator.validateCertificate(cert, otherLogRevoked));

        final MerkleTreeCertificateValidator.ValidationParams wholeLogRevoked =
            new MerkleTreeCertificateValidator.ValidationParams(
                cosigners,
                hashFunc, Collections.<MerkleTreeCertificateValidator.TrustedSubtree>emptyList(),
                Collections.singletonList(MerkleTreeCertificateValidator.RevokedRange.ofLog(logNumber)),
                1
            );
        testException("revoked", "SecurityException", new TestExceptionOperation()
        {
            public void operation()
                throws Exception
            {
                MerkleTreeCertificateValidator.validateCertificate(cert, wholeLogRevoked);
            }
        });

        // Distrust-after (the SCTNotAfter analogue from Section 7.5): the
        // half-open range [serial, 2^64) catches this certificate.
        final MerkleTreeCertificateValidator.ValidationParams distrustAfter =
            new MerkleTreeCertificateValidator.ValidationParams(
                cosigners,
                hashFunc, Collections.<MerkleTreeCertificateValidator.TrustedSubtree>emptyList(),
                Collections.singletonList(
                    MerkleTreeCertificateValidator.RevokedRange.from(BigInteger.valueOf(serial))),
                1
            );
        testException("revoked", "SecurityException", new TestExceptionOperation()
        {
            public void operation()
                throws Exception
            {
                MerkleTreeCertificateValidator.validateCertificate(cert, distrustAfter);
            }
        });

        // [0, serial) does not contain serial, so a minSerial-shaped floor at
        // exactly this serial leaves the certificate valid.
        final MerkleTreeCertificateValidator.ValidationParams floorAtSerial =
            new MerkleTreeCertificateValidator.ValidationParams(
                cosigners,
                hashFunc, Collections.<MerkleTreeCertificateValidator.TrustedSubtree>emptyList(),
                Collections.singletonList(
                    MerkleTreeCertificateValidator.RevokedRange.before(BigInteger.valueOf(serial))),
                1
            );
        isTrue("Floor at exactly this serial leaves the certificate valid",
            MerkleTreeCertificateValidator.validateCertificate(cert, floorAtSerial));
    }

    public void testMalformedInclusionProofLengthRejected()
        throws Exception
    {
        TBSCertificateLogEntry tbsEntry = createDummyTBSCertificateLogEntry();
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(ecdsaKeyPair.getPublic());

        final long serial = (1L << 48) | 42;
        AlgorithmIdentifier sigAlg = new AlgorithmIdentifier(MTCObjectIdentifiers.id_alg_mtcProof);
        TBSCertificate tbs = buildTBSCertificate(tbsEntry, serial, sigAlg, spki);

        // 31 bytes — not a multiple of the SHA-256 hash size, so the proof's
        // hash list cannot be reconstructed.
        org.bouncycastle.cert.plants.MTCProof proof = new org.bouncycastle.cert.plants.MTCProof(
            42, 44, new byte[31], Collections.<MTCCosignature>emptyList());

        final X509CertificateHolder cert = new X509CertificateHolder(
            new DERSequence(new ASN1Encodable[]{tbs, sigAlg, new DERBitString(proof.encode())}).getEncoded());

        final MerkleTreeCertificateValidator.ValidationParams params =
            new MerkleTreeCertificateValidator.ValidationParams(
                new BcMTCCosignerVerifierProvider.Builder().build(),
                hashFunc, Collections.<MerkleTreeCertificateValidator.TrustedSubtree>emptyList(),
                Collections.<MerkleTreeCertificateValidator.RevokedRange>emptyList(),
                1
            );

        // An attacker-controlled inclusion_proof of bad length is a certificate
        // rejection (SecurityException), not an IllegalArgumentException.
        testException("Invalid inclusion proof", "SecurityException", new TestExceptionOperation()
        {
            public void operation()
                throws Exception
            {
                MerkleTreeCertificateValidator.validateCertificate(cert, params);
            }
        });
    }

    public void testSubtreeInfoEquality()
    {
        MerkleTreePrimitives.SubtreeInfo a = new MerkleTreePrimitives.SubtreeInfo(8, 12);
        MerkleTreePrimitives.SubtreeInfo b = new MerkleTreePrimitives.SubtreeInfo(8, 12);
        MerkleTreePrimitives.SubtreeInfo c = new MerkleTreePrimitives.SubtreeInfo(8, 16);

        isTrue("equal intervals compare equal", a.equals(b) && b.equals(a));
        isTrue("equal intervals share a hash code", a.hashCode() == b.hashCode());
        isTrue("different intervals compare unequal", !a.equals(c));
        isTrue("toString names the interval", "[8, 12)".equals(a.toString()));
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

        AlgorithmIdentifier sigAlg = new AlgorithmIdentifier(MTCObjectIdentifiers.id_alg_mtcProof);
        TBSCertificate tbs = buildTBSCertificate(tbsEntry, serial, sigAlg, spki);

        X509CertificateHolder dummyHolder = new X509CertificateHolder(
            new DERSequence(new ASN1Encodable[]{tbs, sigAlg, new DERBitString(new byte[0])}).getEncoded());
        byte[] entryHash = MerkleTreeCertificateValidator.computeEntryHash(dummyHolder, hashFunc);

        byte[] siblingHash = hashFunc.hashLeaf("leaf43".getBytes());
        byte[] subtreeHash = hashFunc.hashNode(entryHash, siblingHash);

        org.bouncycastle.cert.plants.MTCProof proof = new org.bouncycastle.cert.plants.MTCProof(
            start, end, siblingHash, Collections.<MTCCosignature>emptyList());

        DERBitString signatureValue = new DERBitString(proof.encode());
        final X509CertificateHolder cert = new X509CertificateHolder(
            new DERSequence(new ASN1Encodable[]{tbs, sigAlg, signatureValue}).getEncoded());

        List<MerkleTreeCertificateValidator.TrustedSubtree> trusted = new ArrayList<MerkleTreeCertificateValidator.TrustedSubtree>();
        trusted.add(new MerkleTreeCertificateValidator.TrustedSubtree(logNumber, start, end, subtreeHash));

        MerkleTreeCertificateValidator.ValidationParams params =
            new MerkleTreeCertificateValidator.ValidationParams(
                new BcMTCCosignerVerifierProvider.Builder().build(),
                hashFunc, trusted,
                Collections.<MerkleTreeCertificateValidator.RevokedRange>emptyList(),
                1
            );

        isTrue("Landmark certificate validates", MerkleTreeCertificateValidator.validateCertificate(cert, params));

        // No matching trusted subtree => fall through to cosignature checks (none here) => fail.
        final MerkleTreeCertificateValidator.ValidationParams noTrusted =
            new MerkleTreeCertificateValidator.ValidationParams(
                new BcMTCCosignerVerifierProvider.Builder().build(),
                hashFunc, Collections.<MerkleTreeCertificateValidator.TrustedSubtree>emptyList(),
                Collections.<MerkleTreeCertificateValidator.RevokedRange>emptyList(),
                1
            );
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
            logNumber, start, end, hashFunc.hashLeaf("not the right hash".getBytes())));
        final MerkleTreeCertificateValidator.ValidationParams badHash =
            new MerkleTreeCertificateValidator.ValidationParams(
                new BcMTCCosignerVerifierProvider.Builder().build(),
                hashFunc, badHashTrusted,
                Collections.<MerkleTreeCertificateValidator.RevokedRange>emptyList(),
                1
            );
        testException("does not match the trusted subtree", "SecurityException", new TestExceptionOperation()
        {
            public void operation()
                throws Exception
            {
                MerkleTreeCertificateValidator.validateCertificate(cert, badHash);
            }
        });

        // A certificate whose serial claims a different log must not match the
        // log-1 trusted subtree (Section 7.2 step 11 matches on log_number as
        // well as [start, end)). The entry hash excludes the serial, so the
        // log-1 inclusion proof still evaluates to the trusted hash -- only the
        // log binding stops the re-labelled certificate; with no cosignatures
        // it then fails at step 12.
        long otherLogSerial = (2L << 48) | index;
        TBSCertificate otherLogTbs = buildTBSCertificate(tbsEntry, otherLogSerial, sigAlg, spki);
        final X509CertificateHolder otherLogCert = new X509CertificateHolder(
            new DERSequence(new ASN1Encodable[]{otherLogTbs, sigAlg, signatureValue}).getEncoded());
        final MerkleTreeCertificateValidator.ValidationParams log1Trusted =
            new MerkleTreeCertificateValidator.ValidationParams(
                new BcMTCCosignerVerifierProvider.Builder().build(),
                hashFunc, trusted,
                Collections.<MerkleTreeCertificateValidator.RevokedRange>emptyList(),
                1
            );
        testException("Insufficient", "SecurityException", new TestExceptionOperation()
        {
            public void operation()
                throws Exception
            {
                MerkleTreeCertificateValidator.validateCertificate(otherLogCert, log1Trusted);
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
        isTrue("subtree [0, 2) inclusion proof", areEqual(root, computedRoot));
    }

    /**
     * Section 6.2: signatures in an MTCProof MUST be ordered by cosigner_id
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
        List<MTCCosignature> good = new ArrayList<MTCCosignature>();
        good.add(new MTCCosignature(cosignerShort, sigBytes));
        good.add(new MTCCosignature(cosignerLong, sigBytes));
        org.bouncycastle.cert.plants.MTCProof proof = new org.bouncycastle.cert.plants.MTCProof(
            0L, 2L, hashFunc.hashLeaf("x".getBytes()), good);
        isTrue("ordered MTCProof accepted", proof.getSignatures().size() == 2);

        // Wrong order: longer first must be rejected by the constructor.
        final List<MTCCosignature> swapped = new ArrayList<MTCCosignature>();
        swapped.add(new MTCCosignature(cosignerLong, sigBytes));
        swapped.add(new MTCCosignature(cosignerShort, sigBytes));
        testException("not in canonical order", "IllegalArgumentException", new TestExceptionOperation()
        {
            public void operation()
                throws Exception
            {
                new org.bouncycastle.cert.plants.MTCProof(0L, 2L, hashFunc.hashLeaf("x".getBytes()), swapped);
            }
        });

        // Duplicate cosigner_id must also be rejected by the constructor.
        final List<MTCCosignature> dup = new ArrayList<MTCCosignature>();
        dup.add(new MTCCosignature(cosignerShort, sigBytes));
        dup.add(new MTCCosignature(cosignerShort, sigBytes));
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
        baos.write(0); baos.write(0);             // extensions length = 0 (empty list)
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
        baos.write((byte)(sigsBytes.length >>> 16));   // signatures<0..2^24-1>: 3-byte length prefix
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

    /**
     * MTCProof wire format (Section 6.2): the {@code extensions<0..2^16-1>}
     * field precedes {@code start}. An empty list is just the uint16 length
     * prefix 0x0000; a non-empty list round-trips through encode/decode and
     * is reflected in {@link org.bouncycastle.cert.plants.MTCProof#getExtensionsWire()}.
     */
    public void testMTCProofExtensionsEncoding()
        throws Exception
    {
        // Empty extensions list: encode begins with 0x00 0x00 followed by start.
        org.bouncycastle.cert.plants.MTCProof emptyExt = new org.bouncycastle.cert.plants.MTCProof(
            0L, 2L, hashFunc.hashLeaf("x".getBytes()), Collections.<MTCCosignature>emptyList());
        byte[] emptyBytes = emptyExt.encode();
        isTrue("extensions length prefix is 2 bytes 0x0000",
            emptyBytes[0] == 0 && emptyBytes[1] == 0);
        isTrue("getExtensionsWire returns just the 2-byte zero prefix for empty",
            Arrays.equals(new byte[]{0, 0}, emptyExt.getExtensionsWire()));
        org.bouncycastle.cert.plants.MTCProof emptyReparsed = new org.bouncycastle.cert.plants.MTCProof(emptyBytes);
        isTrue("empty extensions round-trip", emptyReparsed.getExtensions().isEmpty());
        isTrue("empty extensions wire round-trip",
            Arrays.equals(new byte[]{0, 0}, emptyReparsed.getExtensionsWire()));

        // Non-empty: two extensions in ascending type order.
        List<MTCLogEntryExtension> exts = new ArrayList<MTCLogEntryExtension>();
        exts.add(new MTCLogEntryExtension(1, new byte[]{1, 2, 3}));
        exts.add(new MTCLogEntryExtension(42, new byte[0]));
        org.bouncycastle.cert.plants.MTCProof proof = new org.bouncycastle.cert.plants.MTCProof(
            exts, 0L, 2L, hashFunc.hashLeaf("x".getBytes()), Collections.<MTCCosignature>emptyList());

        // extensions wire = 2-byte total-length + per-extension (uint16 type + uint16 data_len + data).
        // type=1, data=[1,2,3] → 2 + 2 + 3 = 7 bytes
        // type=42, data=[]   → 2 + 2 + 0 = 4 bytes
        // total body = 11 bytes; wire = 0x000B (11) || body
        byte[] expectedWire = new byte[]{
            0, 11,                          // length prefix
            0, 1,  0, 3,  1, 2, 3,          // extension(1, [1,2,3])
            0, 42, 0, 0                     // extension(42, [])
        };
        isTrue("non-empty extensions wire encoding",
            Arrays.equals(expectedWire, proof.getExtensionsWire()));

        byte[] encoded = proof.encode();
        // Leading bytes of encode() must match getExtensionsWire().
        byte[] leading = new byte[expectedWire.length];
        System.arraycopy(encoded, 0, leading, 0, expectedWire.length);
        isTrue("encode() begins with extensionsWire", Arrays.equals(expectedWire, leading));

        // Round-trip through parser.
        org.bouncycastle.cert.plants.MTCProof reparsed = new org.bouncycastle.cert.plants.MTCProof(encoded);
        isTrue("reparsed extensions list size", reparsed.getExtensions().size() == 2);
        isTrue("reparsed extension[0] type", reparsed.getExtensions().get(0).getExtensionType() == 1);
        isTrue("reparsed extension[0] data",
            Arrays.equals(new byte[]{1, 2, 3}, reparsed.getExtensions().get(0).getExtensionData()));
        isTrue("reparsed extension[1] type", reparsed.getExtensions().get(1).getExtensionType() == 42);
        isTrue("reparsed extension[1] data is empty",
            reparsed.getExtensions().get(1).getExtensionData().length == 0);
    }

    /**
     * MTCProof.extensions MUST be ascending by extension_type with no duplicates;
     * both the constructor and the parser MUST reject violations.
     */
    public void testMTCProofExtensionsOrdering()
        throws Exception
    {
        // Constructor rejects descending order.
        final List<MTCLogEntryExtension> descending = new ArrayList<MTCLogEntryExtension>();
        descending.add(new MTCLogEntryExtension(5, new byte[]{1}));
        descending.add(new MTCLogEntryExtension(1, new byte[]{2}));
        testException("not in ascending order", "IllegalArgumentException", new TestExceptionOperation()
        {
            public void operation()
                throws Exception
            {
                new org.bouncycastle.cert.plants.MTCProof(
                    descending, 0L, 2L, hashFunc.hashLeaf("x".getBytes()),
                    Collections.<MTCCosignature>emptyList());
            }
        });

        // Constructor rejects duplicate extension_type.
        final List<MTCLogEntryExtension> dup = new ArrayList<MTCLogEntryExtension>();
        dup.add(new MTCLogEntryExtension(7, new byte[]{1}));
        dup.add(new MTCLogEntryExtension(7, new byte[]{2}));
        testException("Duplicate extension_type", "IllegalArgumentException", new TestExceptionOperation()
        {
            public void operation()
                throws Exception
            {
                new org.bouncycastle.cert.plants.MTCProof(
                    dup, 0L, 2L, hashFunc.hashLeaf("x".getBytes()),
                    Collections.<MTCCosignature>emptyList());
            }
        });

        // Parser rejects descending: hand-craft bytes with (type=5, []) before (type=1, []).
        // Each extension is 4 bytes header (type uint16, data_len uint16) with empty data,
        // so body = 4 + 4 = 8 bytes, length prefix = 0x0008.
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0); out.write(8);                       // extensions length = 8
        out.write(0); out.write(5); out.write(0); out.write(0);   // type=5, len=0
        out.write(0); out.write(1); out.write(0); out.write(0);   // type=1, len=0
        out.write(new byte[6]);                           // start = 0
        out.write(new byte[6]);                           // end = 0 (invalid as a subtree but parser accepts)
        out.write(0); out.write(0);                       // inclusion_proof length = 0
        out.write(0); out.write(0);                       // signatures length = 0
        final byte[] bytes = out.toByteArray();
        testException("not in ascending order", "IOException", new TestExceptionOperation()
        {
            public void operation()
                throws Exception
            {
                new org.bouncycastle.cert.plants.MTCProof(bytes);
            }
        });
    }

    /**
     * Section 7.2 step 5.2: {@code computeEntryHash} writes the MTCProof's
     * {@code extensions} wire bytes (including the uint16 length prefix) to the
     * hash before the {@code tbs_cert_entry} type. So the entry hash with an
     * empty extensions list differs from one computed with a non-empty list,
     * and the no-extensions overload matches an explicit empty wire.
     */
    public void testEntryHashHonoursExtensionsWire()
        throws Exception
    {
        TBSCertificateLogEntry dummyEntry = createDummyTBSCertificateLogEntry();
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(
            ecdsaKeyPair.getPublic());

        // Build a stand-in certificate so computeEntryHash has something to walk.
        org.bouncycastle.cert.plants.MTCProof emptyProof = new org.bouncycastle.cert.plants.MTCProof(
            0L, 1L, new byte[0], Collections.<MTCCosignature>emptyList());
        X509CertificateHolder cert = org.bouncycastle.cert.plants.LandmarkCertificateManager.buildLandmarkCertificate(
            1, 0, dummyEntry, spki,
            new MerkleTreePrimitives.SubtreeInfo(0, 1),
            Collections.<byte[]>emptyList(),
            hashFunc);

        // No-arg overload matches the empty-wire form (0x0000).
        byte[] hashDefault = MerkleTreeCertificateValidator.computeEntryHash(cert, hashFunc);
        byte[] hashEmptyWire = MerkleTreeCertificateValidator.computeEntryHash(
            cert, emptyProof.getExtensionsWire(), hashFunc);
        isTrue("default overload == empty-wire overload",
            Arrays.equals(hashDefault, hashEmptyWire));

        // A different wire (a single extension) must produce a different hash.
        List<MTCLogEntryExtension> oneExt = Collections.singletonList(
            new MTCLogEntryExtension(99, new byte[]{(byte)0xAA, (byte)0xBB}));
        org.bouncycastle.cert.plants.MTCProof withExt = new org.bouncycastle.cert.plants.MTCProof(
            oneExt, 0L, 1L, new byte[0], Collections.<MTCCosignature>emptyList());
        byte[] hashWithExt = MerkleTreeCertificateValidator.computeEntryHash(
            cert, withExt.getExtensionsWire(), hashFunc);
        isTrue("entry hash changes with non-empty extensions",
            !Arrays.equals(hashDefault, hashWithExt));
    }

    /**
     * Section 5.2.1 MTCLogEntryType enum: {@code null_entry(0)} and
     * {@code tbs_cert_entry(1)}. Lock the values so computeEntryHash's wire
     * output stays in sync with the spec.
     */
    public void testMerkleTreeCertEntryTypeConstants()
        throws Exception
    {
        isTrue("null_entry constant",
            org.bouncycastle.cert.plants.MTCLogEntryType.NULL_ENTRY == 0);
        isTrue("tbs_cert_entry constant",
            org.bouncycastle.cert.plants.MTCLogEntryType.TBS_CERT_ENTRY == 1);
    }

    /**
     * Section 5.5 (draft-06 onwards): MTCCertificationAuthority is
     * {@code SEQUENCE { sigAlg, minSerial, maxSerial }} with the log hash
     * carried by the extension type rather than a {@code logHash} field. A
     * structure in that form is accepted as authority info by the validator;
     * the four-element draft-05 encoding with a leading logHash is rejected.
     */
    public void testAuthorityInfoWithoutLogHash()
        throws Exception
    {
        // Build a minimal valid Merkle Tree cert + provider and validate it
        // against the three-field authority info.
        final long logNumber = 1;
        final long index = 42;
        final long serial = (logNumber << 48) | index;

        TBSCertificateLogEntry tbsEntry = createDummyTBSCertificateLogEntry();
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(ecdsaKeyPair.getPublic());
        AlgorithmIdentifier sigAlg = new AlgorithmIdentifier(MTCObjectIdentifiers.id_alg_mtcProof);
        TBSCertificate tbs = buildTBSCertificate(tbsEntry, serial, sigAlg, spki);
        X509CertificateHolder dummyHolder = new X509CertificateHolder(
            new DERSequence(new ASN1Encodable[]{tbs, sigAlg, new DERBitString(new byte[0])}).getEncoded());
        byte[] entryHash = MerkleTreeCertificateValidator.computeEntryHash(dummyHolder, hashFunc);
        byte[] siblingHash = hashFunc.hashLeaf("leaf43".getBytes());
        byte[] subtreeHash = hashFunc.hashNode(entryHash, siblingHash);

        byte[] cosignedLogId = binaryLogId(LOG_TAID_STRING, logNumber);
        byte[] cosignerId = binaryTrustAnchorID("32473.4");
        byte[] signedData = buildSignatureInput(cosignedLogId, 42, 44, subtreeHash, cosignerId);
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, ed25519KeyPair.getPrivate());
        signer.update(signedData, 0, signedData.length);
        byte[] signature = signer.generateSignature();
        List<MTCCosignature> sigs = Collections.singletonList(new MTCCosignature(cosignerId, signature));
        org.bouncycastle.cert.plants.MTCProof proof = new org.bouncycastle.cert.plants.MTCProof(
            42L, 44L, siblingHash, sigs);
        DERBitString signatureValue = new DERBitString(proof.encode());
        final X509CertificateHolder cert = new X509CertificateHolder(
            new DERSequence(new ASN1Encodable[]{tbs, sigAlg, signatureValue}).getEncoded());

        BcMTCCosignerVerifierProvider cosigners = new BcMTCCosignerVerifierProvider.Builder()
            .addCosigner(cosignerId, ed25519KeyPair.getPublic())
            .build();

        MTCCertificationAuthority matchingAuthority = new MTCCertificationAuthority(
            new AlgorithmIdentifier(MTCObjectIdentifiers.id_alg_mtcProof),
            MTCCertificationAuthority.MIN_SERIAL, MTCCertificationAuthority.MAX_SERIAL);
        MerkleTreeCertificateValidator.ValidationParams matching =
            new MerkleTreeCertificateValidator.ValidationParams(
                cosigners,
                Collections.<MerkleTreeCertificateValidator.TrustedSubtree>emptyList(),
                Collections.<MerkleTreeCertificateValidator.RevokedRange>emptyList(),
                1,
                hashFunc,
                matchingAuthority);
        isTrue("three-field authority info accepted",
            MerkleTreeCertificateValidator.validateCertificate(cert, matching));

        // The structure round-trips as a three-element SEQUENCE.
        MTCCertificationAuthority decoded = MTCCertificationAuthority.getInstance(matchingAuthority.getEncoded());
        isTrue("sigAlg round trip", MTCObjectIdentifiers.id_alg_mtcProof.equals(decoded.getSigAlg().getAlgorithm()));
        isTrue("minSerial round trip", MTCCertificationAuthority.MIN_SERIAL.equals(decoded.getMinSerial()));
        isTrue("maxSerial round trip", MTCCertificationAuthority.MAX_SERIAL.equals(decoded.getMaxSerial()));
        isTrue("three elements", ASN1Sequence.getInstance(matchingAuthority.getEncoded()).size() == 3);

        // The draft-05 shape, with a leading logHash AlgorithmIdentifier, is rejected.
        final ASN1EncodableVector legacy = new ASN1EncodableVector();
        legacy.add(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));
        legacy.add(new AlgorithmIdentifier(MTCObjectIdentifiers.id_alg_mtcProof));
        legacy.add(new ASN1Integer(MTCCertificationAuthority.MIN_SERIAL));
        legacy.add(new ASN1Integer(MTCCertificationAuthority.MAX_SERIAL));
        testException("SEQUENCE of 3 elements", "IllegalArgumentException", new TestExceptionOperation()
        {
            public void operation()
                throws Exception
            {
                MTCCertificationAuthority.getInstance(new DERSequence(legacy));
            }
        });

        // Serials below mtcMinSerial (2^48) are outside the type's range.
        testException("minSerial out of range", "IllegalArgumentException", new TestExceptionOperation()
        {
            public void operation()
                throws Exception
            {
                new MTCCertificationAuthority(
                    new AlgorithmIdentifier(MTCObjectIdentifiers.id_alg_mtcProof),
                    BigIntegers.ZERO, MTCCertificationAuthority.MAX_SERIAL);
            }
        });
    }

    /**
     * The draft-05 class names survive as deprecated subclasses of the draft-07
     * ones, so code written against them still compiles, interoperates with the
     * new names, and produces identical encodings.
     */
    @SuppressWarnings("deprecation")
    public void testDeprecatedNames()
        throws Exception
    {
        byte[] cosignerId = binaryTrustAnchorID("32473.4");
        byte[] sigBytes = new byte[]{1, 2, 3};
        MTCSignature oldSig = new MTCSignature(cosignerId, sigBytes);
        isTrue("MTCSignature is an MTCCosignature", oldSig instanceof MTCCosignature);
        List<MTCSignature> oldSigs = new ArrayList<MTCSignature>();
        oldSigs.add(oldSig);
        byte[] leaf = hashFunc.hashLeaf("x".getBytes());
        org.bouncycastle.cert.plants.MTCProof viaOld = new org.bouncycastle.cert.plants.MTCProof(0L, 2L, leaf, oldSigs);
        org.bouncycastle.cert.plants.MTCProof viaNew = new org.bouncycastle.cert.plants.MTCProof(0L, 2L, leaf,
            Collections.singletonList(new MTCCosignature(cosignerId, sigBytes)));
        isTrue("MTCProof encodes identically from either name", areEqual(viaOld.encode(), viaNew.encode()));
        isTrue("getSignatures returns the new type", viaOld.getSignatures().get(0) instanceof MTCCosignature);

        MerkleTreeCertEntryExtension oldExt = new MerkleTreeCertEntryExtension(7, new byte[]{9});
        isTrue("extension is an MTCLogEntryExtension", oldExt instanceof MTCLogEntryExtension);
        List<MerkleTreeCertEntryExtension> oldExts = new ArrayList<MerkleTreeCertEntryExtension>();
        oldExts.add(oldExt);
        isEquals(MTCLogEntryType.TBS_CERT_ENTRY, MerkleTreeCertEntryType.TBS_CERT_ENTRY);
        MerkleTreeCertEntry oldEntry = new MerkleTreeCertEntry(oldExts, MerkleTreeCertEntryType.NULL_ENTRY, new byte[0]);
        MTCLogEntry newEntry = new MTCLogEntry(
            Collections.singletonList(new MTCLogEntryExtension(7, new byte[]{9})), MTCLogEntryType.NULL_ENTRY, new byte[0]);
        isTrue("entry is an MTCLogEntry", oldEntry instanceof MTCLogEntry);
        isTrue("log entry encodes identically from either name", areEqual(oldEntry.encode(), newEntry.encode()));
        isTrue("log entry reparses through the old name",
            areEqual(new MerkleTreeCertEntry(newEntry.encode()).encode(), newEntry.encode()));

        byte[] logId = binaryLogId(LOG_TAID_STRING, 1);
        isTrue("cosigned subtree encodes identically from either name", areEqual(
            MTCCosignedMessage.encode(logId, 0L, 2L, leaf, cosignerId),
            MTCCosignedSubtree.encode(logId, 0L, 2L, leaf, cosignerId)));
    }

    /**
     * Section 6.2 (draft-07): a CA MAY include GREASE cosignatures, an unused
     * cosigner ID with an arbitrary byte string as the signature, and
     * Section 7.2 step 12 has the relying party ignore cosigners it does not
     * recognise. A proof carrying GREASE entries on either side of the real
     * cosignature, in canonical order, must validate exactly as without them,
     * and GREASE alone must not satisfy the cosigner requirement.
     */
    public void testGreaseCosignaturesIgnored()
        throws Exception
    {
        final long logNumber = 1;
        final long index = 42;
        final long serial = (logNumber << 48) | index;

        TBSCertificateLogEntry tbsEntry = createDummyTBSCertificateLogEntry();
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(ecdsaKeyPair.getPublic());
        AlgorithmIdentifier sigAlg = new AlgorithmIdentifier(MTCObjectIdentifiers.id_alg_mtcProof);
        TBSCertificate tbs = buildTBSCertificate(tbsEntry, serial, sigAlg, spki);
        X509CertificateHolder dummyHolder = new X509CertificateHolder(
            new DERSequence(new ASN1Encodable[]{tbs, sigAlg, new DERBitString(new byte[0])}).getEncoded());
        byte[] entryHash = MerkleTreeCertificateValidator.computeEntryHash(dummyHolder, hashFunc);
        byte[] siblingHash = hashFunc.hashLeaf("leaf43".getBytes());
        byte[] subtreeHash = hashFunc.hashNode(entryHash, siblingHash);

        byte[] cosignedLogId = binaryLogId(LOG_TAID_STRING, logNumber);
        byte[] cosignerId = binaryTrustAnchorID("32473.4");
        byte[] signedData = buildSignatureInput(cosignedLogId, 42, 44, subtreeHash, cosignerId);
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, ed25519KeyPair.getPrivate());
        signer.update(signedData, 0, signedData.length);
        byte[] signature = signer.generateSignature();

        // GREASE IDs that sort before (shorter) and after (longer) the real one.
        byte[] greaseShort = binaryTrustAnchorID("32473");
        byte[] greaseLong = binaryTrustAnchorID("32473.4.99");
        byte[] junk = new byte[37];
        new SecureRandom().nextBytes(junk);
        List<MTCCosignature> sigs = new ArrayList<MTCCosignature>();
        sigs.add(new MTCCosignature(greaseShort, junk));
        sigs.add(new MTCCosignature(cosignerId, signature));
        sigs.add(new MTCCosignature(greaseLong, new byte[0]));
        org.bouncycastle.cert.plants.MTCProof proof = new org.bouncycastle.cert.plants.MTCProof(
            42L, 44L, siblingHash, sigs);
        org.bouncycastle.cert.plants.MTCProof reparsed = new org.bouncycastle.cert.plants.MTCProof(proof.encode());
        isEquals(3, reparsed.getSignatures().size());
        X509CertificateHolder cert = new X509CertificateHolder(
            new DERSequence(new ASN1Encodable[]{tbs, sigAlg, new DERBitString(proof.encode())}).getEncoded());

        BcMTCCosignerVerifierProvider cosigners = new BcMTCCosignerVerifierProvider.Builder()
            .addCosigner(cosignerId, ed25519KeyPair.getPublic())
            .build();
        MerkleTreeCertificateValidator.ValidationParams params =
            new MerkleTreeCertificateValidator.ValidationParams(cosigners, hashFunc,
                Collections.<MerkleTreeCertificateValidator.TrustedSubtree>emptyList(),
                Collections.<MerkleTreeCertificateValidator.RevokedRange>emptyList(), 1);
        isTrue("GREASE cosignatures are ignored", MerkleTreeCertificateValidator.validateCertificate(cert, params));

        // GREASE alone does not meet the requirement for one valid cosignature.
        List<MTCCosignature> greaseOnly = new ArrayList<MTCCosignature>();
        greaseOnly.add(new MTCCosignature(greaseShort, junk));
        greaseOnly.add(new MTCCosignature(greaseLong, new byte[0]));
        org.bouncycastle.cert.plants.MTCProof greaseProof = new org.bouncycastle.cert.plants.MTCProof(
            42L, 44L, siblingHash, greaseOnly);
        final X509CertificateHolder greaseCert = new X509CertificateHolder(
            new DERSequence(new ASN1Encodable[]{tbs, sigAlg, new DERBitString(greaseProof.encode())}).getEncoded());
        final MerkleTreeCertificateValidator.ValidationParams greaseParams = params;
        testException("cosign", "SecurityException", new TestExceptionOperation()
        {
            public void operation()
                throws Exception
            {
                MerkleTreeCertificateValidator.validateCertificate(greaseCert, greaseParams);
            }
        });
    }

    /**
     * Section 5.5: {@code minSerial} sets a lower bound the CA undertakes not to
     * have issued below. The validator rejects any cert whose serial is below
     * {@code authorityInfo.getMinSerial()} when the authority info is supplied.
     */
    public void testValidatorEnforcesMinSerial()
        throws Exception
    {
        // Build a Merkle Tree cert with serial = (logNumber=1, index=10) = 0x0001_0000000000_0A.
        final long logNumber = 1;
        final long index = 10;
        final BigInteger serial = BigInteger.valueOf((logNumber << 48) | index);

        TBSCertificateLogEntry tbsEntry = createDummyTBSCertificateLogEntry();
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(ecdsaKeyPair.getPublic());
        AlgorithmIdentifier sigAlg = new AlgorithmIdentifier(MTCObjectIdentifiers.id_alg_mtcProof);
        TBSCertificate tbs = buildTBSCertificate(tbsEntry, BigIntegers.longValueExact(serial), sigAlg, spki);

        // The MTCProof has [10, 11) — a single-leaf subtree, so no inclusion siblings.
        org.bouncycastle.cert.plants.MTCProof proof = new org.bouncycastle.cert.plants.MTCProof(
            10L, 11L, new byte[0], Collections.<MTCCosignature>emptyList());
        DERBitString signatureValue = new DERBitString(proof.encode());
        final X509CertificateHolder cert = new X509CertificateHolder(
            new DERSequence(new ASN1Encodable[]{tbs, sigAlg, signatureValue}).getEncoded());

        BcMTCCosignerVerifierProvider cosigners = new BcMTCCosignerVerifierProvider.Builder().build();

        // minSerial above the cert's serial — must be rejected.
        final MTCCertificationAuthority strictMinSerial = new MTCCertificationAuthority(
            new AlgorithmIdentifier(MTCObjectIdentifiers.id_alg_mtcProof),
            serial.add(BigIntegers.ONE), MTCCertificationAuthority.MAX_SERIAL);
        final MerkleTreeCertificateValidator.ValidationParams tooHigh =
            new MerkleTreeCertificateValidator.ValidationParams(
                cosigners,
                Collections.<MerkleTreeCertificateValidator.TrustedSubtree>emptyList(),
                Collections.<MerkleTreeCertificateValidator.RevokedRange>emptyList(),
                0,
                hashFunc,
                strictMinSerial);
        testException("below CA minSerial", "SecurityException", new TestExceptionOperation()
        {
            public void operation()
                throws Exception
            {
                MerkleTreeCertificateValidator.validateCertificate(cert, tooHigh);
            }
        });

        // maxSerial below the cert's serial — must be rejected.
        final MTCCertificationAuthority strictMaxSerial = new MTCCertificationAuthority(
            new AlgorithmIdentifier(MTCObjectIdentifiers.id_alg_mtcProof),
            MTCCertificationAuthority.MIN_SERIAL, serial.subtract(BigIntegers.ONE));
        final MerkleTreeCertificateValidator.ValidationParams tooLow =
            new MerkleTreeCertificateValidator.ValidationParams(
                cosigners,
                Collections.<MerkleTreeCertificateValidator.TrustedSubtree>emptyList(),
                Collections.<MerkleTreeCertificateValidator.RevokedRange>emptyList(),
                0,
                hashFunc,
                strictMaxSerial);
        testException("above CA maxSerial", "SecurityException", new TestExceptionOperation()
        {
            public void operation()
                throws Exception
            {
                MerkleTreeCertificateValidator.validateCertificate(cert, tooLow);
            }
        });

        // minSerial equal to the cert's serial — accepted (boundary).
        // (Validation will then fail on the cosignature requirement, but only
        // after the minSerial check; testing the minSerial gate in isolation
        // here would require a passing-everything-else cert, which the previous
        // logHash test already covers. Instead, check minSerial=0 with the
        // same throw-it-away cosignature policy: 0 cosignatures required and
        // the subtree is single-leaf so the inclusion-proof step succeeds.)
        MTCCertificationAuthority openMinSerial = new MTCCertificationAuthority(
            new AlgorithmIdentifier(MTCObjectIdentifiers.id_alg_mtcProof),
            MTCCertificationAuthority.MIN_SERIAL, MTCCertificationAuthority.MAX_SERIAL);
        MerkleTreeCertificateValidator.ValidationParams permissive =
            new MerkleTreeCertificateValidator.ValidationParams(
                cosigners,
                Collections.<MerkleTreeCertificateValidator.TrustedSubtree>emptyList(),
                Collections.<MerkleTreeCertificateValidator.RevokedRange>emptyList(),
                0,
                hashFunc,
                openMinSerial);
        isTrue("minSerial = 0 admits any positive serial",
            MerkleTreeCertificateValidator.validateCertificate(cert, permissive));
    }

    /**
     * MTCSignatureAlgorithm constants are BC's own names (the draft fixes no
     * algorithm list) and must stay as published. A typo here silently breaks cosignature
     * dispatch in both Bc and Jca verifiers.
     */
    public void testSignatureAlgorithmConstants()
        throws Exception
    {
        isTrue("ECDSA-P256-SHA256",
            "ECDSA-P256-SHA256".equals(
                org.bouncycastle.cert.plants.MTCSignatureAlgorithm.ECDSA_P256_SHA256));
        isTrue("ECDSA-P384-SHA384",
            "ECDSA-P384-SHA384".equals(
                org.bouncycastle.cert.plants.MTCSignatureAlgorithm.ECDSA_P384_SHA384));
        isTrue("Ed25519",
            "Ed25519".equals(org.bouncycastle.cert.plants.MTCSignatureAlgorithm.ED25519));
        isTrue("ML-DSA-44",
            "ML-DSA-44".equals(org.bouncycastle.cert.plants.MTCSignatureAlgorithm.ML_DSA_44));
        isTrue("ML-DSA-65",
            "ML-DSA-65".equals(org.bouncycastle.cert.plants.MTCSignatureAlgorithm.ML_DSA_65));
        isTrue("ML-DSA-87",
            "ML-DSA-87".equals(org.bouncycastle.cert.plants.MTCSignatureAlgorithm.ML_DSA_87));
    }

    /**
     * MTCLogEntry should round-trip through encode/parse, and the
     * tbs_cert_entry body must decode into the same TBSCertificateLogEntry the
     * encoder started from.
     */
    public void testMerkleTreeCertEntryRoundTrip()
        throws Exception
    {
        TBSCertificateLogEntry original = createDummyTBSCertificateLogEntry();

        // tbs_cert_entry_data = DER body of the TBSCertificateLogEntry (no SEQUENCE wrapper).
        byte[] tbsDer = original.getEncoded(ASN1Encoding.DER);
        // Skip the leading SEQUENCE tag + length (DER tag 0x30 then minimum-length octets).
        int contentOff;
        int lenByte = tbsDer[1] & 0xFF;
        if ((lenByte & 0x80) == 0)
        {
            contentOff = 2;
        }
        else
        {
            contentOff = 2 + (lenByte & 0x7F);
        }
        byte[] tbsBody = new byte[tbsDer.length - contentOff];
        System.arraycopy(tbsDer, contentOff, tbsBody, 0, tbsBody.length);

        // Empty extensions, type = tbs_cert_entry.
        org.bouncycastle.cert.plants.MTCLogEntry entry =
            new org.bouncycastle.cert.plants.MTCLogEntry(
                Collections.<MTCLogEntryExtension>emptyList(),
                org.bouncycastle.cert.plants.MTCLogEntryType.TBS_CERT_ENTRY,
                tbsBody);

        byte[] encoded = entry.encode();
        // Leading bytes: 0x00 0x00 (empty extensions length) || 0x00 0x01 (type=tbs_cert_entry).
        isTrue("entry encoding starts with empty extensions + tbs_cert_entry type",
            encoded[0] == 0 && encoded[1] == 0 && encoded[2] == 0 && encoded[3] == 1);

        org.bouncycastle.cert.plants.MTCLogEntry parsed =
            new org.bouncycastle.cert.plants.MTCLogEntry(encoded);
        isTrue("type round-trips",
            parsed.getType() == org.bouncycastle.cert.plants.MTCLogEntryType.TBS_CERT_ENTRY);
        isTrue("extensions round-trip empty", parsed.getExtensions().isEmpty());
        isTrue("body round-trips", Arrays.equals(tbsBody, parsed.getBody()));

        // getTbsCertEntry() reattaches the SEQUENCE wrapper and decodes successfully.
        TBSCertificateLogEntry decoded = parsed.getTbsCertEntry();
        isTrue("TBSCertificateLogEntry round-trips through SEQUENCE wrapping",
            Arrays.equals(original.getEncoded(ASN1Encoding.DER), decoded.getEncoded(ASN1Encoding.DER)));
    }

    /**
     * The CA logs an {@code MTCLogEntry} built from a {@code TBSCertificateLogEntry}
     * (Section 5.2.1) and the relying party recomputes the entry from the
     * TBSCertificate (Section 7.2 steps 7 to 9); the two leaf hashes must be the
     * same bytes, or no certificate would ever verify. The TBSCertificate here
     * carries every optional field - explicit v3 version, both unique IDs and
     * extensions - so the tagged-field handling on both sides is covered, with
     * an empty and a non-empty log-entry extensions list. The log entry is also
     * taken back to a TBSCertificate through the landmark builder (Section 6.2
     * requires the copied fields to be equal) and re-read through the
     * {@code MTCLogEntry} parser.
     */
    public void testEntryHashMatchesLogEntryEncoding()
        throws Exception
    {
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(ecdsaKeyPair.getPublic());
        byte[] spkiHash = hashFunc.hashRaw(spki.getEncoded(ASN1Encoding.DER));
        AlgorithmIdentifier sigAlg = new AlgorithmIdentifier(MTCObjectIdentifiers.id_alg_mtcProof);
        long now = System.currentTimeMillis();

        V3TBSCertificateGenerator tbsGen = new V3TBSCertificateGenerator();
        tbsGen.setSerialNumber(new ASN1Integer(TrustAnchorIDs.certSerial(1, 42)));
        tbsGen.setSignature(sigAlg);
        tbsGen.setIssuer(TrustAnchorIDs.issuerName(LOG_TAID_STRING));
        tbsGen.setStartDate(new Time(new Date(now)));
        tbsGen.setEndDate(new Time(new Date(now + 86400000L)));
        tbsGen.setSubject(new X500Name("CN=mtc-test-ee"));
        tbsGen.setSubjectPublicKeyInfo(spki);
        tbsGen.setIssuerUniqueID(new DERBitString(new byte[]{1, 2, 3}));
        tbsGen.setSubjectUniqueID(new DERBitString(new byte[]{4, 5}));
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        extGen.addExtension(Extension.subjectAlternativeName, false,
            new GeneralNames(new GeneralName(GeneralName.dNSName, "example.com")));
        tbsGen.setExtensions(extGen.generate());
        TBSCertificate tbs = tbsGen.generateTBSCertificate();

        TBSCertificateLogEntry logEntry = new TBSCertificateLogEntry(tbs, spkiHash);
        isTrue("log entry keeps the unique IDs and extensions",
            logEntry.getIssuerUniqueID() != null && logEntry.getSubjectUniqueID() != null
                && logEntry.getExtensions() != null);
        byte[] entryBody = derContents(logEntry.getEncoded(ASN1Encoding.DER));

        List<List<MTCLogEntryExtension>> extensionLists = new ArrayList<List<MTCLogEntryExtension>>();
        extensionLists.add(Collections.<MTCLogEntryExtension>emptyList());
        List<MTCLogEntryExtension> two = new ArrayList<MTCLogEntryExtension>();
        two.add(new MTCLogEntryExtension(3, new byte[]{(byte)0xAA}));
        two.add(new MTCLogEntryExtension(0xF000, new byte[0]));
        extensionLists.add(two);

        for (List<MTCLogEntryExtension> exts : extensionLists)
        {
            String name = exts.size() + " log-entry extension(s)";
            org.bouncycastle.cert.plants.MTCProof proof = new org.bouncycastle.cert.plants.MTCProof(
                exts, 42L, 43L, new byte[0], Collections.<MTCCosignature>emptyList());

            // CA side: MTH({entry}) over the encoded MTCLogEntry.
            MTCLogEntry entry = new MTCLogEntry(exts, MTCLogEntryType.TBS_CERT_ENTRY, entryBody);
            byte[] caSide = hashFunc.hashLeaf(entry.encode());

            // Relying party side: from the TBSCertificate, and from the certificate carrying the proof.
            byte[] fromTbs = MerkleTreeCertificateValidator.computeEntryHash(tbs, proof.getExtensionsWire(), hashFunc);
            isTrue(name + ": entry hash from the TBSCertificate equals the log entry hash", areEqual(caSide, fromTbs));
            X509CertificateHolder cert = new X509CertificateHolder(
                new DERSequence(new ASN1Encodable[]{tbs, sigAlg, new DERBitString(proof.encode())}).getEncoded());
            isTrue(name + ": entry hash from the certificate equals the log entry hash",
                areEqual(caSide, MerkleTreeCertificateValidator.computeEntryHash(cert, proof.getExtensionsWire(), hashFunc)));

            // The log entry re-read through the wire parser is the original structure.
            TBSCertificateLogEntry reparsed = new MTCLogEntry(entry.encode()).getTbsCertEntry();
            isTrue(name + ": log entry round-trips through MTCLogEntry",
                areEqual(logEntry.getEncoded(ASN1Encoding.DER), reparsed.getEncoded(ASN1Encoding.DER)));
        }

        // The landmark builder reconstructs the TBSCertificate from the log entry, unique IDs
        // and extensions included, so its certificate hashes to the same entry.
        X509CertificateHolder rebuilt = org.bouncycastle.cert.plants.LandmarkCertificateManager.buildLandmarkCertificate(
            1, 42, logEntry, spki, new MerkleTreePrimitives.SubtreeInfo(42, 43), Collections.<byte[]>emptyList(), hashFunc);
        isTrue("landmark builder reproduces the TBSCertificate", areEqual(
            tbs.getEncoded(ASN1Encoding.DER),
            rebuilt.toASN1Structure().getTBSCertificate().getEncoded(ASN1Encoding.DER)));

        // A log entry hashing a different subject key is a different entry.
        TBSCertificateLogEntry otherKey = new TBSCertificateLogEntry(tbs, hashFunc.hashRaw(Strings.toByteArray("other key")));
        byte[] otherKeyHash = hashFunc.hashLeaf(new MTCLogEntry(Collections.<MTCLogEntryExtension>emptyList(),
            MTCLogEntryType.TBS_CERT_ENTRY, derContents(otherKey.getEncoded(ASN1Encoding.DER))).encode());
        isTrue("a different subjectPublicKeyInfoHash gives a different entry hash",
            !areEqual(otherKeyHash, MerkleTreeCertificateValidator.computeEntryHash(tbs, hashFunc)));
    }

    /** The contents octets of a DER SEQUENCE, i.e. the encoding without its identifier and length octets. */
    private static byte[] derContents(byte[] der)
    {
        int lenByte = der[1] & 0xFF;
        int contentOff = (lenByte & 0x80) == 0 ? 2 : 2 + (lenByte & 0x7F);
        byte[] contents = new byte[der.length - contentOff];
        System.arraycopy(der, contentOff, contents, 0, contents.length);
        return contents;
    }

    /**
     * The streaming {@code writeEntryHashInput} helper must produce the exact
     * byte sequence that {@code computeEntryHash} hashes — otherwise the
     * single-pass option in Section 7.2 would diverge from the buffered path.
     */
    public void testWriteEntryHashInputMatchesComputeEntryHash()
        throws Exception
    {
        TBSCertificateLogEntry tbsEntry = createDummyTBSCertificateLogEntry();
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(
            ecdsaKeyPair.getPublic());
        X509CertificateHolder cert = org.bouncycastle.cert.plants.LandmarkCertificateManager.buildLandmarkCertificate(
            1, 0, tbsEntry, spki,
            new MerkleTreePrimitives.SubtreeInfo(0, 1),
            Collections.<byte[]>emptyList(),
            hashFunc);

        byte[] extensionsWire = new byte[]{0, 0};
        ByteArrayOutputStream streamed = new ByteArrayOutputStream();
        MerkleTreeCertificateValidator.writeEntryHashInput(cert, extensionsWire, hashFunc, streamed);
        byte[] streamedHash = hashFunc.hashLeaf(streamed.toByteArray());

        byte[] bufferedHash = MerkleTreeCertificateValidator.computeEntryHash(
            cert, extensionsWire, hashFunc);
        isTrue("streamed entry-hash input matches buffered computeEntryHash output",
            Arrays.equals(bufferedHash, streamedHash));
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

    private static final byte[] SUBTREE_LABEL = new byte[]{
        's', 'u', 'b', 't', 'r', 'e', 'e', '/', 'v', '1', (byte)0x0A, (byte)0x00
    };

    /**
     * Builds a CosignedMessage per Section 5.3.1 for the MTCProof
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
        v.add(new ASN1Integer(serialNumber));  // serialNumber per Section 6.2: (log_number << 48) | index
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
        // Section 5.1: the issuer name has a single RDN with attribute type
        // id-rdna-trustAnchorID and a RELATIVE-OID value carrying the CA ID.
        X500Name issuer = TrustAnchorIDs.issuerName(LOG_TAID_STRING);

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
        testProofGeneration();
        testNodeSourceProofGeneration();
        testFindCoveringSubtrees();
        testValidSubtreeCheck();
        testCosignatureVerificationECDSA();
        testCosignatureVerificationEcdsaP384();
        testCosignatureVerificationEd25519();
        testCosignatureVerificationMlDsa44();
        testCosignatureVerificationMlDsa65();
        testCosignatureVerificationMlDsa87();
        testMTCSignatureVerifierProviderManualMode();
        testMTCSignatureVerifierProviderCertificateMode();
        testCertificateModeGeneralSubtree();
        testStandaloneCertificateValidation();
        testMalformedInclusionProofLengthRejected();
        testSubtreeInfoEquality();
        testLandmarkCertificateValidation();
        testInclusionProofTwoLeaf();
        testMTCProofCosignerOrdering();
        testMTCProofExtensionsEncoding();
        testMTCProofExtensionsOrdering();
        testEntryHashHonoursExtensionsWire();
        testMerkleTreeCertEntryTypeConstants();
        testAuthorityInfoWithoutLogHash();
        testGreaseCosignaturesIgnored();
        testDeprecatedNames();
        testValidatorEnforcesMinSerial();
        testSignatureAlgorithmConstants();
        testMerkleTreeCertEntryRoundTrip();
        testEntryHashMatchesLogEntryEncoding();
        testWriteEntryHashInputMatchesComputeEntryHash();
    }

    public static void main(String[] args)
    {
        runTest(new MerkleTreeCertificatesTest());
    }
}
