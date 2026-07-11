package org.bouncycastle.cert.plants.test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
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
import org.bouncycastle.cert.plants.MTCCertificationAuthorityCertificate;
import org.bouncycastle.cert.plants.TrustAnchorIDs;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Tests for the new features added in draft-ietf-plants-merkle-tree-certs-04:
 * trust anchor ID helpers (Section 5.1), CA certificate representation
 * (Section 5.5), and landmark sequence parsing (Section 6.3.3).
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

        // Section 3 / 4.1 of draft-ietf-tls-trust-anchor-ids: a trust anchor ID's
        // binary form is opaque<1..2^8-1>, i.e. 1..255 bytes. Reject an empty caId,
        // an ID whose encoding would exceed 255 bytes, and an over-long fromDottedDecimal.
        testException("binary length must be 1..255", "IllegalArgumentException", new TestExceptionOperation()
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
        final byte[] caId255 = TrustAnchorIDs.fromDottedDecimal(maxSb.toString());
        isTrue("255-byte trust anchor ID is accepted", caId255.length == TrustAnchorIDs.MAX_ID_LENGTH);
        testException("binary length must be 1..255", "IllegalArgumentException", new TestExceptionOperation()
        {
            public void operation()
            {
                // appending the log arc + number tips a 255-byte caId over 255 bytes
                TrustAnchorIDs.logId(caId255, 1);
            }
        });

        StringBuilder overSb = new StringBuilder("1");
        for (int i = 1; i <= TrustAnchorIDs.MAX_ID_LENGTH; i++)
        {
            overSb.append(".1");
        }
        final String over255Dotted = overSb.toString();   // 256 single-octet components
        testException("binary length must be 1..255", "IllegalArgumentException", new TestExceptionOperation()
        {
            public void operation()
            {
                TrustAnchorIDs.fromDottedDecimal(over255Dotted);
            }
        });

        // Serial composition per Section 6.1: serial = (log_number << 48) | index,
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
            new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256),
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

        // Subject decoding.
        byte[] decodedCaId = MTCCertificationAuthorityCertificate.extractCaId(cert);
        isTrue("CA ID round-trips through certificate subject", areEqual(caId, decodedCaId));

        // Extension content.
        MTCCertificationAuthority decoded =
            MTCCertificationAuthorityCertificate.extractAuthorityInfo(cert);
        isTrue("logHash preserved",
            NISTObjectIdentifiers.id_sha256.equals(decoded.getLogHash().getAlgorithm()));
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
        // Synthetic sequence: last landmark = 5, 3 active, tree sizes
        // (newest-first) 1000, 800, 500, 200. last_landmark - 3 = 2, so the
        // oldest landmark in this view is landmark 2 with tree size 200.
        String text =
            "5 3\n" +
            "1000\n" +
            "800\n" +
            "500\n" +
            "200\n";

        LandmarkSequence seq = LandmarkSequence.parse(text);
        isEquals(5L, seq.getLastLandmark());
        isEquals(3, seq.getNumActiveLandmarks());
        isEquals(1000L, seq.getTreeSize(5));
        isEquals(800L, seq.getTreeSize(4));
        isEquals(500L, seq.getTreeSize(3));
        isEquals(200L, seq.getTreeSize(2));

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

        // Active landmark subtrees: for each consecutive pair (oldest first)
        // [200, 500), [500, 800), [800, 1000), find_subtrees covers each.
        List<long[]> subtrees = seq.activeLandmarkSubtrees();
        isTrue("at least 3 subtree intervals (one per gap)", subtrees.size() >= 3);
        // Subtree starts must be non-decreasing.
        for (int i = 1; i < subtrees.size(); i++)
        {
            isTrue("subtree intervals non-decreasing", subtrees.get(i)[0] >= subtrees.get(i - 1)[0]);
        }
    }

    private void testLandmarkSequenceRejectsBadInput()
    {
        // Tree sizes not strictly decreasing.
        testException("must be strictly monotonically decreasing", "IOException", new TestExceptionOperation()
        {
            public void operation()
                throws IOException
            {
                LandmarkSequence.parse("3 2\n500\n500\n100\n");
            }
        });

        // Wrong number of lines for the announced num_active_landmarks.
        testException("expected", "IOException", new TestExceptionOperation()
        {
            public void operation()
                throws IOException
            {
                LandmarkSequence.parse("3 2\n500\n100\n");
            }
        });

        // num_active_landmarks > last_landmark.
        testException("num_active_landmarks", "IOException", new TestExceptionOperation()
        {
            public void operation()
                throws IOException
            {
                LandmarkSequence.parse("2 5\n500\n400\n300\n200\n100\n0\n");
            }
        });
    }

    public static void main(String[] args)
    {
        runTest(new MTCNewFeaturesTest());
    }
}
