package org.bouncycastle.cert.plants.test;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import org.bouncycastle.cert.plants.MTCCosignedMessage;
import org.bouncycastle.cert.plants.MTCCosignerVerifier;
import org.bouncycastle.cert.plants.MTCSignatureVerifier;
import org.bouncycastle.cert.plants.MerkleTreeHash;
import org.bouncycastle.cert.plants.TrustAnchorIDs;
import org.bouncycastle.cert.plants.bc.BcSha256MerkleTreeHash;
import org.bouncycastle.cert.plants.jcajce.JcaMTCCosignerVerifierProvider;
import org.bouncycastle.cert.plants.jcajce.JcaMTCSignatureVerifier;
import org.bouncycastle.cert.plants.jcajce.JcaSha256MerkleTreeHash;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Tests for the JCA-side ({@code .jcajce}) operator implementations of the
 * Merkle Tree Certificate package: {@link JcaSha256MerkleTreeHash},
 * {@link JcaMTCSignatureVerifier}, and {@link JcaMTCCosignerVerifierProvider}.
 *
 * <p>Where applicable the JCA outputs are cross-checked against the lightweight
 * {@code BcSha256MerkleTreeHash} so that callers can mix the two flavours behind
 * the same {@link MerkleTreeHash} / {@link MTCSignatureVerifier} interfaces.</p>
 */
public class JcajceOperatorsTest
    extends SimpleTest
{
    public String getName()
    {
        return "JcajceOperators";
    }

    public void performTest()
        throws Exception
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        testJcaSha256MerkleTreeHashAgainstBc();
        testMerkleTreeHashSharedInstanceThreadSafety();
        testJcaSignatureVerifierEcdsaP256();
        testJcaSignatureVerifierEcdsaP384();
        testJcaSignatureVerifierEd25519();
        testJcaSignatureVerifierMlDsa44();
        testJcaSignatureVerifierMlDsa65();
        testJcaSignatureVerifierMlDsa87();
        testJcaSignatureVerifierUnsupportedAlgorithmRejected();
        testJcaCosignerVerifierProviderAutoDetect();
        testJcaCosignerVerifierProviderMissingCosignerReturnsNull();
    }

    private void testJcaSha256MerkleTreeHashAgainstBc()
    {
        MerkleTreeHash bc = new BcSha256MerkleTreeHash();
        MerkleTreeHash jca = new JcaSha256MerkleTreeHash("BC");

        isTrue("hash size matches", bc.getHashSize() == jca.getHashSize());
        isTrue("hash size is 32", jca.getHashSize() == 32);

        byte[] entry = "leaf entry data".getBytes();
        isTrue("hashLeaf matches BC",
            Arrays.areEqual(bc.hashLeaf(entry), jca.hashLeaf(entry)));

        byte[] left = bc.hashLeaf("left".getBytes());
        byte[] right = bc.hashLeaf("right".getBytes());
        isTrue("hashNode matches BC",
            Arrays.areEqual(bc.hashNode(left, right), jca.hashNode(left, right)));

        byte[] raw = "raw bytes".getBytes();
        isTrue("hashRaw matches BC",
            Arrays.areEqual(bc.hashRaw(raw), jca.hashRaw(raw)));

        // Default-helper constructor should also work.
        MerkleTreeHash defaultHelper = new JcaSha256MerkleTreeHash();
        isTrue("default-helper output matches",
            Arrays.areEqual(jca.hashLeaf(entry), defaultHelper.hashLeaf(entry)));
    }

    private void testMerkleTreeHashSharedInstanceThreadSafety()
        throws Exception
    {
        checkHashThreadSafety("Bc", new BcSha256MerkleTreeHash());
        checkHashThreadSafety("Jca", new JcaSha256MerkleTreeHash("BC"));
    }

    /**
     * Regression test: a single MerkleTreeHash instance ends up shared via
     * MTCCertAuth / ValidationParams, so the bindings must not carry digest
     * state between calls. Hammers one instance from several threads and
     * checks every output against the single-threaded result.
     */
    private void checkHashThreadSafety(String flavour, final MerkleTreeHash hash)
        throws Exception
    {
        final byte[] entry = "shared instance leaf entry".getBytes();
        final byte[] left = hash.hashLeaf("left".getBytes());
        final byte[] right = hash.hashLeaf("right".getBytes());
        final byte[] expectedLeaf = hash.hashLeaf(entry);
        final byte[] expectedNode = hash.hashNode(left, right);
        final byte[] expectedRaw = hash.hashRaw(entry);

        final CountDownLatch start = new CountDownLatch(1);
        final AtomicInteger failures = new AtomicInteger();

        Thread[] threads = new Thread[4];
        for (int i = 0; i != threads.length; i++)
        {
            threads[i] = new Thread(new Runnable()
            {
                public void run()
                {
                    try
                    {
                        start.await();
                        for (int j = 0; j != 2000; j++)
                        {
                            if (!Arrays.areEqual(expectedLeaf, hash.hashLeaf(entry))
                                || !Arrays.areEqual(expectedNode, hash.hashNode(left, right))
                                || !Arrays.areEqual(expectedRaw, hash.hashRaw(entry)))
                            {
                                failures.incrementAndGet();
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        // A corrupted shared digest can also surface as an exception;
                        // count it rather than letting the thread die silently.
                        failures.incrementAndGet();
                    }
                }
            });
            threads[i].start();
        }
        start.countDown();
        for (int i = 0; i != threads.length; i++)
        {
            threads[i].join();
        }

        isTrue(flavour + " hash binding corrupted output when shared across threads",
            failures.get() == 0);
    }

    private void testJcaSignatureVerifierEcdsaP256()
        throws Exception
    {
        KeyPair kp = generateEcKeyPair("P-256");

        byte[] message = buildCosignedMessage("32473.1.0.1", "32473.2", 100, 200, 32);
        byte[] signature = signJca(kp, "SHA256WITHPLAIN-ECDSA", message);

        MTCSignatureVerifier v = new JcaMTCSignatureVerifier.Builder()
            .setProvider("BC").build("ECDSA-P256-SHA256", kp.getPublic());
        isTrue("ECDSA-P256 cosignature verifies", v.verify(message, signature));
        isTrue("bound algorithm surfaced", "ECDSA-P256-SHA256".equals(v.getAlgorithm()));

        // The detect-based build overload must arrive at the same algorithm.
        MTCSignatureVerifier detected = new JcaMTCSignatureVerifier.Builder()
            .setProvider("BC").build(kp.getPublic());
        isTrue("ECDSA-P256 detect-based verifier verifies", detected.verify(message, signature));

        signature[0] ^= 0x01;
        isTrue("ECDSA-P256 tampered signature rejected", !v.verify(message, signature));
    }

    private void testJcaSignatureVerifierEcdsaP384()
        throws Exception
    {
        KeyPair kp = generateEcKeyPair("P-384");

        byte[] message = buildCosignedMessage("32473.1.0.1", "32473.3", 0, 1024, 32);
        byte[] signature = signJca(kp, "SHA384WITHPLAIN-ECDSA", message);

        MTCSignatureVerifier v = new JcaMTCSignatureVerifier.Builder()
            .setProvider("BC").build("ECDSA-P384-SHA384", kp.getPublic());
        isTrue("ECDSA-P384 cosignature verifies", v.verify(message, signature));

        signature[signature.length - 1] ^= 0x55;
        isTrue("ECDSA-P384 tampered signature rejected", !v.verify(message, signature));
    }

    private void testJcaSignatureVerifierEd25519()
        throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("Ed25519", "BC").generateKeyPair();

        byte[] message = buildCosignedMessage("32473.1.0.1", "32473.4", 5, 50, 32);
        byte[] signature = signJca(kp, "Ed25519", message);

        MTCSignatureVerifier v = new JcaMTCSignatureVerifier.Builder()
            .setProvider("BC").build("Ed25519", kp.getPublic());
        isTrue("Ed25519 cosignature verifies", v.verify(message, signature));

        signature[10] ^= 0x80;
        isTrue("Ed25519 tampered signature rejected", !v.verify(message, signature));
    }

    private void testJcaSignatureVerifierMlDsa44()
        throws Exception
    {
        testJcaSignatureVerifierMlDsa("ML-DSA-44", "32473.5");
    }

    private void testJcaSignatureVerifierMlDsa65()
        throws Exception
    {
        testJcaSignatureVerifierMlDsa("ML-DSA-65", "32473.6");
    }

    private void testJcaSignatureVerifierMlDsa87()
        throws Exception
    {
        testJcaSignatureVerifierMlDsa("ML-DSA-87", "32473.7");
    }

    private void testJcaSignatureVerifierMlDsa(String alg, String cosignerDotted)
        throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance(alg, "BC").generateKeyPair();

        byte[] message = buildCosignedMessage("32473.1.0.1", cosignerDotted, 0, 100, 32);
        byte[] signature = signJca(kp, alg, message);

        MTCSignatureVerifier v = new JcaMTCSignatureVerifier.Builder()
            .setProvider("BC").build(alg, kp.getPublic());
        isTrue(alg + " cosignature verifies", v.verify(message, signature));

        signature[signature.length / 2] ^= 0x01;
        isTrue(alg + " tampered signature rejected", !v.verify(message, signature));
    }

    private void testJcaSignatureVerifierUnsupportedAlgorithmRejected()
        throws Exception
    {
        final KeyPair kp = generateEcKeyPair("P-256");
        testException("Unsupported algorithm", "IllegalArgumentException", new TestExceptionOperation()
        {
            public void operation()
            {
                new JcaMTCSignatureVerifier.Builder().setProvider("BC").build("BOGUS", kp.getPublic())
                    .verify(new byte[0], new byte[0]);
            }
        });
    }

    private void testJcaCosignerVerifierProviderAutoDetect()
        throws Exception
    {
        // Build a provider that holds three cosigners (ECDSA P-256, Ed25519, ML-DSA-65),
        // each registered with the typed-key convenience overload so the algorithm
        // is auto-detected. Then verify a signature against each through the operator.
        KeyPair ec256 = generateEcKeyPair("P-256");
        KeyPair ed = KeyPairGenerator.getInstance("Ed25519", "BC").generateKeyPair();
        KeyPair ml = KeyPairGenerator.getInstance("ML-DSA-65", "BC").generateKeyPair();

        byte[] ec256Id = TrustAnchorIDs.fromDottedDecimal("32473.10");
        byte[] edId = TrustAnchorIDs.fromDottedDecimal("32473.11");
        byte[] mlId = TrustAnchorIDs.fromDottedDecimal("32473.12");

        JcaMTCCosignerVerifierProvider provider = new JcaMTCCosignerVerifierProvider.Builder()
            .setProvider("BC")
            .addCosigner(ec256Id, ec256.getPublic())
            .addCosigner(edId, ed.getPublic())
            .addCosigner(mlId, ml.getPublic())
            .build();

        verifyThroughProvider(provider, ec256, ec256Id, "SHA256WITHPLAIN-ECDSA");
        verifyThroughProvider(provider, ed, edId, "Ed25519");
        verifyThroughProvider(provider, ml, mlId, "ML-DSA-65");
    }

    private void testJcaCosignerVerifierProviderMissingCosignerReturnsNull()
        throws Exception
    {
        KeyPair kp = generateEcKeyPair("P-256");
        byte[] registeredId = TrustAnchorIDs.fromDottedDecimal("32473.20");
        byte[] missingId = TrustAnchorIDs.fromDottedDecimal("32473.99");

        JcaMTCCosignerVerifierProvider provider = new JcaMTCCosignerVerifierProvider.Builder()
            .setProvider("BC")
            .addCosigner(registeredId, kp.getPublic())
            .build();

        isTrue("registered cosigner is found", provider.get(registeredId) != null);
        isTrue("bound cosigner ID surfaced",
            Arrays.areEqual(registeredId, provider.get(registeredId).getCosignerId()));
        isTrue("unknown cosigner returns null", provider.get(missingId) == null);
    }

    private void verifyThroughProvider(
        JcaMTCCosignerVerifierProvider provider,
        KeyPair kp,
        byte[] cosignerId,
        String jcaSignatureAlg)
        throws Exception
    {
        byte[] logId = TrustAnchorIDs.fromDottedDecimal("32473.1.0.1");
        byte[] subtreeHash = new byte[32];
        new Random(0x42).nextBytes(subtreeHash);

        byte[] message = MTCCosignedMessage.encode(logId, 0L, 100L, 200L, subtreeHash, cosignerId);
        byte[] signature = signJca(kp, jcaSignatureAlg, message);

        MTCCosignerVerifier verifier = provider.get(cosignerId);
        isTrue("cosigner verifier present for " + jcaSignatureAlg, verifier != null);
        isTrue("cosignature verifies via provider for " + jcaSignatureAlg,
            verifyMessage(verifier, message, signature));
    }

    private static KeyPair generateEcKeyPair(String curveName)
        throws Exception
    {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");
        g.initialize(new ECGenParameterSpec(curveName));
        return g.generateKeyPair();
    }

    private static byte[] signJca(KeyPair kp, String jcaSignatureAlg, byte[] message)
        throws Exception
    {
        Signature sig = Signature.getInstance(jcaSignatureAlg, "BC");
        sig.initSign(kp.getPrivate());
        sig.update(message);
        return sig.sign();
    }

    private static boolean verifyMessage(ContentVerifier v, byte[] message, byte[] signature)
        throws IOException
    {
        v.getOutputStream().write(message);
        return v.verify(signature);
    }

    private static byte[] buildCosignedMessage(
        String logIdDotted, String cosignerIdDotted, long start, long end, int subtreeHashLen)
        throws Exception
    {
        byte[] logId = TrustAnchorIDs.fromDottedDecimal(logIdDotted);
        byte[] cosignerId = TrustAnchorIDs.fromDottedDecimal(cosignerIdDotted);
        byte[] subtreeHash = new byte[subtreeHashLen];
        new Random(end ^ start).nextBytes(subtreeHash);
        return MTCCosignedMessage.encode(logId, 0L, start, end, subtreeHash, cosignerId);
    }

    public static void main(String[] args)
    {
        runTest(new JcajceOperatorsTest());
    }
}
