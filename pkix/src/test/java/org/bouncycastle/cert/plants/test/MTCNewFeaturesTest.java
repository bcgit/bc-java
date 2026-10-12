package org.bouncycastle.cert.plants.test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1RelativeOID;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.MTCCertificationAuthority;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.plants.LandmarkSequence;
import org.bouncycastle.cert.plants.MerkleTreePrimitives;
import org.bouncycastle.cert.plants.MTCCertificationAuthorityCertificate;
import org.bouncycastle.cert.plants.TrustAnchorIDs;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Tests for the trust anchor ID helpers (draft-ietf-plants-merkle-tree-certs-07
 * Section 5.1, bounded at 32 bytes per draft-ietf-tls-trust-anchor-ids-06
 * Section 4), the CA certificate representation (Section 5.5), the published
 * landmark document (Section 6.4.3) and the landmark-relative certificate
 * construction (Section 6.4.4).
 */
public class MTCNewFeaturesTest
    extends SimpleTest
{
    public String getName()
    {
        return "MTCNewFeatures";
    }

    public void performTest()
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());
        testTrustAnchorIDs();
        testCaCertificateBuildAndParse();
        testLandmarkSequenceParseAndFormat();
        testLandmarkSequenceRejectsBadInput();
    }

    private void testTrustAnchorIDs()
        throws Exception
    {
        final byte[] caId = TrustAnchorIDs.fromDottedDecimal("32473.1");

        // Round-trip via dotted decimal.
        isTrue("CA ID dotted-decimal round-trip",
            "32473.1".equals(TrustAnchorIDs.toDottedDecimal(caId)));

        // Log ID = caID || 0 || logNumber. For "32473.1" + log 1 => "32473.1.0.1".
        byte[] logId = TrustAnchorIDs.logId(caId, 1);
        isTrue("log ID dotted form",
            "32473.1.0.1".equals(TrustAnchorIDs.toDottedDecimal(logId)));

        // Landmark ID per Section 8.2: caID 1 logN landmarkL => "32473.1.1.8.42"
        byte[] landmarkId = TrustAnchorIDs.landmarkId(caId, 8, 42);
        isTrue("landmark ID dotted form",
            "32473.1.1.8.42".equals(TrustAnchorIDs.toDottedDecimal(landmarkId)));

        // Landmark-group ID per Section 8.2.1: caID 2 logN landmarkL => "32473.1.2.8.42"
        byte[] groupId = TrustAnchorIDs.landmarkGroupId(caId, 8, 42);
        isTrue("landmark group ID dotted form",
            "32473.1.2.8.42".equals(TrustAnchorIDs.toDottedDecimal(groupId)));

        // log_number must be in [1, 65535].
        testException("out of range", "IllegalArgumentException", new TestExceptionOperation()
        {
            public void operation()
            {
                TrustAnchorIDs.logId(caId, 0);
            }
        });
        testException("out of range", "IllegalArgumentException", new TestExceptionOperation()
        {
            public void operation()
            {
                TrustAnchorIDs.logId(caId, 0x10000L);
            }
        });

        // Section 5.1 allocates landmark / landmark-group OIDs for positive
        // landmark numbers only; landmark 0 has no subtrees and needs no ID.
        testException("must be positive", "IllegalArgumentException", new TestExceptionOperation()
        {
            public void operation()
            {
                TrustAnchorIDs.landmarkId(caId, 8, 0);
            }
        });
        testException("must be positive", "IllegalArgumentException", new TestExceptionOperation()
        {
            public void operation()
            {
                TrustAnchorIDs.landmarkGroupId(caId, 8, 0);
            }
        });

        // Section 4 of draft-ietf-tls-trust-anchor-ids-06: a trust anchor ID's
        // binary form is opaque<1..32>, i.e. 1..32 bytes. Reject an empty caId,
        // an ID whose encoding would exceed 32 bytes, and an over-long fromDottedDecimal.
        testException("binary length must be 1..32", "IllegalArgumentException", new TestExceptionOperation()
        {
            public void operation()
            {
                TrustAnchorIDs.logId(new byte[0], 1);
            }
        });

        StringBuilder maxSb = new StringBuilder("1");
        for (int i = 1; i < TrustAnchorIDs.MAX_ID_LENGTH; i++)
        {
            maxSb.append(".1");
        }
        final byte[] caId32 = TrustAnchorIDs.fromDottedDecimal(maxSb.toString());
        isTrue("32-byte trust anchor ID is accepted", caId32.length == TrustAnchorIDs.MAX_ID_LENGTH);
        testException("binary length must be 1..32", "IllegalArgumentException", new TestExceptionOperation()
        {
            public void operation()
            {
                // appending the log arc + number tips a 32-byte caId over 32 bytes
                TrustAnchorIDs.logId(caId32, 1);
            }
        });

        StringBuilder overSb = new StringBuilder("1");
        for (int i = 1; i <= TrustAnchorIDs.MAX_ID_LENGTH; i++)
        {
            overSb.append(".1");
        }
        final String over32Dotted = overSb.toString();   // 33 single-octet components
        testException("binary length must be 1..32", "IllegalArgumentException", new TestExceptionOperation()
        {
            public void operation()
            {
                TrustAnchorIDs.fromDottedDecimal(over32Dotted);
            }
        });

        // Serial composition per Section 6.2: serial = (log_number << 48) | index,
        // "positive and at most 2^64-1". log_number >= 32768 overflows a signed
        // long shift, so the composition must be done in BigInteger.
        isTrue("small serial",
            BigInteger.valueOf((1L << 48) | 42).equals(TrustAnchorIDs.certSerial(1, 42)));
        BigInteger highSerial = TrustAnchorIDs.certSerial(32768, 5);
        isTrue("high-log-number serial is positive", highSerial.signum() > 0);
        isTrue("high-log-number serial value",
            new BigInteger("8000000000000005", 16).equals(highSerial));
        isTrue("maximum serial is 2^64-1",
            new BigInteger("ffffffffffffffff", 16).equals(
                TrustAnchorIDs.certSerial(0xFFFF, 0xFFFFFFFFFFFFL)));
    }

    private void testCaCertificateBuildAndParse()
        throws Exception
    {
        byte[] caId = TrustAnchorIDs.fromDottedDecimal("32473.1");

        // Generate an EC P-256 keypair to act as the cosigner key for the CA.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
        kpg.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        KeyPair cosignerKp = kpg.generateKeyPair();
        SubjectPublicKeyInfo cosignerSpki = SubjectPublicKeyInfo.getInstance(
            cosignerKp.getPublic().getEncoded());

        // A separate "external CA" key signs the structure (Section 5.5 says the
        // MTC CA SHOULD NOT self-sign). We do not assert the signature is
        // standards-compliant here; the test exercises the structural fields.
        KeyPair externalKp = kpg.generateKeyPair();

        MTCCertificationAuthority info = new MTCCertificationAuthority(
            new AlgorithmIdentifier(new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.2.840.10045.4.3.2")), // ecdsa-with-SHA256
            BigInteger.valueOf(1L << 48),                // minSerial: first entry of log 1
            BigInteger.valueOf((2L << 48) - 1));         // maxSerial: last entry of log 1

        X500Name externalIssuer = new X500Name("CN=External Trust Anchor");
        BigInteger serial = BigInteger.ONE;
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 86400000L);

        X509v3CertificateBuilder builder = MTCCertificationAuthorityCertificate.newBuilder(
            externalIssuer, serial, notBefore, notAfter, caId, cosignerSpki, info);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
            .setProvider("BC").build(externalKp.getPrivate());
        X509CertificateHolder cert = builder.build(signer);

        // Subject decoding: a single RDN carrying the CA ID as a RELATIVE-OID
        // under id-rdna-trustAnchorID (Section 5.1).
        byte[] decodedCaId = MTCCertificationAuthorityCertificate.extractCaId(cert);
        isTrue("CA ID round-trips through certificate subject", areEqual(caId, decodedCaId));
        RDN[] subjectRdns = cert.getSubject().getRDNs();
        isTrue("single RDN", subjectRdns.length == 1 && subjectRdns[0].getTypesAndValues().length == 1);
        isTrue("id-rdna-trustAnchorID is 1.3.6.1.5.5.7.25.3",
            "1.3.6.1.5.5.7.25.3".equals(subjectRdns[0].getFirst().getType().getId()));
        isTrue("subject value is a RELATIVE-OID",
            subjectRdns[0].getFirst().getValue().toASN1Primitive() instanceof ASN1RelativeOID);
        isTrue("RELATIVE-OID is the CA ID",
            "32473.1".equals(((ASN1RelativeOID)subjectRdns[0].getFirst().getValue().toASN1Primitive()).getId()));

        // Extension content: the type identifies the log hash (Section 7.1).
        isTrue("extension is id-pe-mtcCertificationAuthority-SHA256 (1.3.6.1.5.5.7.1.38)",
            cert.getExtension(new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.38")) != null);
        isTrue("log hash from extension type is SHA-256",
            NISTObjectIdentifiers.id_sha256.equals(
                MTCCertificationAuthorityCertificate.logHashAlgorithm(cert).getAlgorithm()));
        MTCCertificationAuthority decoded =
            MTCCertificationAuthorityCertificate.extractAuthorityInfo(cert);
        isTrue("sigAlg preserved",
            "1.2.840.10045.4.3.2".equals(decoded.getSigAlg().getAlgorithm().getId()));
        isTrue("minSerial preserved",
            decoded.getMinSerial().equals(BigInteger.valueOf(1L << 48)));
        isTrue("maxSerial preserved",
            decoded.getMaxSerial().equals(BigInteger.valueOf((2L << 48) - 1)));

        // Required X.509 extensions.
        Extension keyUsageExt = cert.getExtensions().getExtension(Extension.keyUsage);
        isTrue("keyUsage extension present and critical", keyUsageExt != null && keyUsageExt.isCritical());
        KeyUsage ku = KeyUsage.getInstance(keyUsageExt.getParsedValue());
        isTrue("keyCertSign asserted", ku.hasUsages(KeyUsage.keyCertSign));

        Extension bcExt = cert.getExtensions().getExtension(Extension.basicConstraints);
        isTrue("basicConstraints extension present and critical", bcExt != null && bcExt.isCritical());
        BasicConstraints bc = BasicConstraints.getInstance(bcExt.getParsedValue());
        isTrue("cA flag set", bc.isCA());

        // id-pe-mtcCertificationAuthority must be critical.
        Extension authExt = cert.getExtensions().getExtension(
            MTCCertificationAuthorityCertificate.EXTENSION_OID);
        isTrue("authority extension is critical", authExt.isCritical());
    }

    private void testLandmarkSequenceParseAndFormat()
        throws Exception
    {
        // Section 6.4.3: a header of latest_landmark, then "<tree_size> <expiry>"
        // per landmark newest first. latest_landmark = 5 with four lines, so the
        // oldest landmark in this view is landmark 2. Evaluated at time 5000,
        // landmarks 5, 4 and 3 are active and landmark 2 has expired.
        final long now = 5000;
        String text =
            "5\n" +
            "1000 9000\n" +
            "800 8000\n" +
            "500 8000\n" +
            "200 4000\n";

        LandmarkSequence seq = LandmarkSequence.parse(text, now);
        isEquals(5L, seq.getLastLandmark());
        isEquals(2L, seq.getOldestLandmark());
        isEquals(3, seq.getNumActiveLandmarks());
        isEquals(1000L, seq.getTreeSize(5));
        isEquals(800L, seq.getTreeSize(4));
        isEquals(500L, seq.getTreeSize(3));
        isEquals(200L, seq.getTreeSize(2));
        isEquals(9000L, seq.getExpiry(5));
        isEquals(4000L, seq.getExpiry(2));
        isTrue("landmark 5 active", seq.isActive(5, now));
        isTrue("landmark 3 active", seq.isActive(3, now));
        isTrue("landmark 2 expired", !seq.isActive(2, now));
        isTrue("landmark 5 expired at its expiry", !seq.isActive(5, 9000));

        // Out-of-window lookups must throw.
        try
        {
            seq.getTreeSize(1);
            fail("expected IndexOutOfBoundsException for landmark before window");
        }
        catch (IndexOutOfBoundsException expected)
        {
            // pass
        }

        // Format must round-trip.
        String reformatted = seq.format();
        isTrue("format round-trips", text.equals(reformatted));

        // Landmark subtrees (Section 6.4.1): the two covering subtrees of the
        // entries since the previous landmark.
        List<long[]> l3 = seq.landmarkSubtrees(3);
        isEquals(2, l3.size());
        List<long[]> cover = MerkleTreePrimitives.findCoveringSubtrees(200, 500);
        isEquals(cover.get(0)[0], l3.get(0)[0]);
        isEquals(cover.get(0)[1], l3.get(0)[1]);
        isEquals(cover.get(1)[0], l3.get(1)[0]);
        isEquals(cover.get(1)[1], l3.get(1)[1]);

        // Active landmark subtrees: two per active landmark, oldest first.
        List<long[]> subtrees = seq.activeLandmarkSubtrees(now);
        isEquals(6, subtrees.size());
        isEquals(cover.get(0)[0], subtrees.get(0)[0]);
        isEquals(1000L, subtrees.get(5)[1]);
        for (int i = 1; i < subtrees.size(); i++)
        {
            isTrue("subtree intervals non-decreasing", subtrees.get(i)[0] >= subtrees.get(i - 1)[0]);
        }
        isEquals(2, seq.activeLandmarkSubtrees(8000).size());   // landmarks 3 and 4 expire at 8000
        isEquals(0, seq.activeLandmarkSubtrees(9000).size());

        // Section 6.4.4: the landmark for an entry is the lowest numbered one
        // whose tree size exceeds the index, and the subtree is the one of its
        // two that contains the index.
        isEquals(3L, seq.landmarkFor(499));
        isEquals(4L, seq.landmarkFor(500));
        isEquals(5L, seq.landmarkFor(999));
        isEquals(-1L, seq.landmarkFor(1000));
        long[] sub = seq.landmarkSubtreeFor(250);
        isTrue("subtree contains 250", sub != null && sub[0] <= 250 && 250 < sub[1]);
        isTrue("subtree is a landmark 3 subtree", sub[0] == l3.get(0)[0] || sub[0] == l3.get(1)[0]);
        isTrue("no subtree yet for 1000", seq.landmarkSubtreeFor(1000) == null);
        // Entry 100 lies under landmark 2, whose predecessor is outside the window.
        isEquals(2L, seq.landmarkFor(100));
        isTrue("predecessor outside window", seq.landmarkSubtreeFor(100) == null);

        // A window reaching landmark 0: its subtrees are [0, 0) twice and it is never active.
        LandmarkSequence fromZero = LandmarkSequence.parse("1\n4 9000\n0 0\n", now);
        List<long[]> l0 = fromZero.landmarkSubtrees(0);
        isEquals(2, l0.size());
        isTrue("landmark 0 subtrees are empty", l0.get(0)[0] == 0 && l0.get(0)[1] == 0 && l0.get(1)[1] == 0);
        isTrue("landmark 0 never active", !fromZero.isActive(0, -1));
        isEquals(2, fromZero.activeLandmarkSubtrees(now).size());
        isTrue("[0, 2) holds entry 1", fromZero.landmarkSubtreeFor(1)[0] == 0 && fromZero.landmarkSubtreeFor(1)[1] == 2);
    }

    private void testLandmarkSequenceRejectsBadInput()
    {
        // Tree sizes not strictly decreasing.
        testException("must be strictly monotonically decreasing", "IOException", new TestExceptionOperation()
        {
            public void operation()
                throws IOException
            {
                LandmarkSequence.parse("3\n500 9000\n500 8000\n100 0\n", 5000);
            }
        });

        // Expiry times not monotonically decreasing.
        testException("expiration times must be monotonically decreasing", "IOException", new TestExceptionOperation()
        {
            public void operation()
                throws IOException
            {
                LandmarkSequence.parse("3\n500 8000\n400 9000\n100 0\n", 5000);
            }
        });

        // More landmarks than latest_landmark allows.
        testException("more landmarks", "IOException", new TestExceptionOperation()
        {
            public void operation()
                throws IOException
            {
                LandmarkSequence.parse("2\n500 9000\n400 9000\n300 9000\n200 0\n", 5000);
            }
        });

        // No expired landmark to delimit the active set.
        testException("no expired landmark", "IOException", new TestExceptionOperation()
        {
            public void operation()
                throws IOException
            {
                LandmarkSequence.parse("3\n500 9000\n400 8000\n", 5000);
            }
        });

        // Landmark 0 must have tree size 0 and expiry 0.
        testException("landmark 0 must have", "IOException", new TestExceptionOperation()
        {
            public void operation()
                throws IOException
            {
                LandmarkSequence.parse("1\n500 9000\n0 10\n", 5000);
            }
        });

        // Strict syntax: the old two-field header, a missing expiry, extraneous
        // whitespace, and a missing trailing newline are all rejected.
        testException("not a decimal integer", "IOException", new TestExceptionOperation()
        {
            public void operation()
                throws IOException
            {
                LandmarkSequence.parse("3 2\n500 9000\n100 0\n", 5000);
            }
        });
        testException("must be \"<tree_size> <expiry>\"", "IOException", new TestExceptionOperation()
        {
            public void operation()
                throws IOException
            {
                LandmarkSequence.parse("3\n500\n100 0\n", 5000);
            }
        });
        testException("must be \"<tree_size> <expiry>\"", "IOException", new TestExceptionOperation()
        {
            public void operation()
                throws IOException
            {
                LandmarkSequence.parse("3\n500 9000 \n100 0\n", 5000);
            }
        });
        testException("must end with a newline", "IOException", new TestExceptionOperation()
        {
            public void operation()
                throws IOException
            {
                LandmarkSequence.parse("3\n500 9000\n100 0", 5000);
            }
        });
        testException("exceeds 2^48-1", "IOException", new TestExceptionOperation()
        {
            public void operation()
                throws IOException
            {
                LandmarkSequence.parse("3\n281474976710656 9000\n100 0\n", 5000);
            }
        });
    }

    public static void main(String[] args)
    {
        runTest(new MTCNewFeaturesTest());
    }
}
