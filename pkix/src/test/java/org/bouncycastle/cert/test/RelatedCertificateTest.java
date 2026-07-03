package org.bouncycastle.cert.test;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.BinaryTime;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.RequesterCertificate;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.RelatedCertificate;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.RelatedCertificateTool;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.util.Arrays;

/**
 * Tests for the RFC 9763 wire-format types ({@link RelatedCertificate} extension
 * and {@link RequesterCertificate} CSR attribute) plus the
 * {@link RelatedCertificateTool} convenience helpers.
 */
public class RelatedCertificateTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    public void setUp()
    {
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // =====================================================================
    // OID + extension constants
    // =====================================================================

    public void testOidValues()
    {
        assertEquals("1.3.6.1.5.5.7.1.36", X509ObjectIdentifiers.id_pe_relatedCert.getId());
        assertEquals("1.3.6.1.5.5.7.1.36", Extension.relatedCertificate.getId());
        assertEquals(X509ObjectIdentifiers.id_pe_relatedCert, Extension.relatedCertificate);
        assertEquals("1.2.840.113549.1.9.16.2.60", PKCSObjectIdentifiers.id_aa_relatedCertRequest.getId());
    }

    // =====================================================================
    // BinaryTime
    // =====================================================================

    public void testBinaryTimeRoundTrip()
        throws Exception
    {
        // Pick a fixed epoch-second value to anchor the wire encoding.
        long sec = 1700000000L;
        BinaryTime t = new BinaryTime(sec);
        assertTrue(t.getTime().hasValue(sec));

        BinaryTime reparsed = BinaryTime.getInstance(t.getEncoded());
        assertEquals(t, reparsed);
        assertTrue(reparsed.getTime().hasValue(sec));

        BinaryTime fromDate = new BinaryTime(new Date(sec * 1000L));
        assertEquals(t, fromDate);
        assertEquals(sec * 1000L, fromDate.toDate().getTime());
    }

    public void testBinaryTimeRejectsNegative()
    {
        try
        {
            new BinaryTime(-1L);
            fail("BinaryTime accepted negative seconds");
        }
        catch (IllegalArgumentException expected) {}

        try
        {
            new BinaryTime(new Date(-1L));
            fail("BinaryTime accepted pre-epoch Date");
        }
        catch (IllegalArgumentException expected) {}
    }

    // =====================================================================
    // RelatedCertificate extension ASN.1
    // =====================================================================

    public void testRelatedCertificateRoundTrip()
        throws Exception
    {
        AlgorithmIdentifier sha256 = new AlgorithmIdentifier(
            new org.bouncycastle.asn1.ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"));
        byte[] hash = new byte[32];
        new SecureRandom().nextBytes(hash);

        RelatedCertificate ext = new RelatedCertificate(sha256, new DEROctetString(hash));
        RelatedCertificate reparsed = RelatedCertificate.getInstance(ext.getEncoded());

        assertEquals(sha256, reparsed.getHashAlgorithm());
        assertTrue(Arrays.areEqual(hash, reparsed.getHashValue().getOctets()));
    }

    // =====================================================================
    // RelatedCertificateTool — extension creation / verification
    // =====================================================================

    public void testCreateAndVerifyRelatedCertificateExtension()
        throws Exception
    {
        X509CertificateHolder relatedCert = generateSelfSignedECCert("CN=related-cert");
        X509CertificateHolder otherCert = generateSelfSignedECCert("CN=other-cert");

        DigestCalculatorProvider digestProv = new BcDigestCalculatorProvider();
        DigestCalculator sha256 = digestProv.get(DigestCalculator.SHA_256);

        RelatedCertificate ext = RelatedCertificateTool.createRelatedCertificate(relatedCert, sha256);

        assertEquals(DigestCalculator.SHA_256, ext.getHashAlgorithm());
        assertEquals(32, ext.getHashValue().getOctets().length);

        assertTrue(RelatedCertificateTool.isRelatedCertificate(ext, relatedCert, digestProv));
        assertFalse("extension should not match an unrelated cert",
            RelatedCertificateTool.isRelatedCertificate(ext, otherCert, digestProv));

        // Wire-survival: round-trip through DER and verify the parsed value
        // is still recognised as belonging to relatedCert.
        RelatedCertificate parsed = RelatedCertificate.getInstance(ext.getEncoded());
        assertTrue(RelatedCertificateTool.isRelatedCertificate(parsed, relatedCert, digestProv));
    }

    // =====================================================================
    // RequesterCertificate ASN.1 round trip
    // =====================================================================

    public void testRequesterCertificateRoundTrip()
        throws Exception
    {
        IssuerAndSerialNumber certID = new IssuerAndSerialNumber(
            new X500Name("CN=Issuer"), BigInteger.valueOf(0x1234567890L));
        BinaryTime ts = new BinaryTime(1700000000L);
        String[] uris = new String[] {
            "https://example.com/certs/abc.cer",
            "data:application/pkix-cert;base64,Zm9v"
        };
        byte[] sig = new byte[64];
        new SecureRandom().nextBytes(sig);

        RequesterCertificate value = new RequesterCertificate(certID, ts, uris, sig);
        RequesterCertificate parsed = RequesterCertificate.getInstance(value.getEncoded());

        assertEquals(certID, parsed.getCertID());
        assertEquals(ts, parsed.getRequestTime());
        assertTrue(Arrays.areEqual(uris, parsed.getLocationInfo()));
        assertTrue(Arrays.areEqual(sig, parsed.getSignature().getOctets()));
    }

    public void testRequesterCertificateRejectsEmptyUriList()
    {
        try
        {
            new RequesterCertificate(
                new IssuerAndSerialNumber(new X500Name("CN=I"), BigInteger.ONE),
                new BinaryTime(1L),
                new String[0],
                new byte[16]);
            fail("RequesterCertificate accepted empty URI list");
        }
        catch (IllegalArgumentException expected) {}
    }

    // =====================================================================
    // signature-input pinning — RFC 9763 sec. 4.1 says "concatenation of
    // DER-encoded IssuerAndSerialNumber and BinaryTime", NOT a SEQUENCE.
    // =====================================================================

    public void testSignatureInputLayout()
        throws Exception
    {
        IssuerAndSerialNumber certID = new IssuerAndSerialNumber(
            new X500Name("CN=Issuer"), BigInteger.valueOf(0x42));
        BinaryTime ts = new BinaryTime(1700000000L);

        byte[] expected = concat(
            certID.getEncoded(ASN1Encoding.DER),
            ts.getEncoded(ASN1Encoding.DER));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        RelatedCertificateTool.writeSignatureInput(bOut, certID, ts);

        assertTrue("signature input must be DER(certID)||DER(requestTime), no SEQUENCE wrapper",
            Arrays.areEqual(expected, bOut.toByteArray()));
    }

    // =====================================================================
    // Sign/verify round-trip with the helper
    // =====================================================================

    public void testCreateAndVerifyRequesterCertificate()
        throws Exception
    {
        KeyPair kp = ecKeyPair();
        IssuerAndSerialNumber certID = new IssuerAndSerialNumber(
            new X500Name("CN=related-cert"), BigInteger.valueOf(99));
        BinaryTime ts = new BinaryTime(new Date());
        String[] uris = new String[] { "https://example.com/related.cer" };

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
            .setProvider(BC).build(kp.getPrivate());
        RequesterCertificate value = RelatedCertificateTool.createRequesterCertificate(
            certID, ts, uris, signer);

        // Round-trip through DER so we exercise the parser path.
        RequesterCertificate parsed = RequesterCertificate.getInstance(value.getEncoded());

        ContentVerifierProvider verifierProv = new JcaContentVerifierProviderBuilder()
            .setProvider(BC).build(kp.getPublic());
        ContentVerifier verifier = verifierProv.get(signer.getAlgorithmIdentifier());

        assertTrue("RequesterCertificate signature must verify under signer's public key",
            RelatedCertificateTool.verifyRequesterCertificate(parsed, verifier));

        // And the verify must reject a tampered request time.
        RequesterCertificate tampered = new RequesterCertificate(
            certID, new BinaryTime(ts.getTime().longValueExact() + 1), uris, value.getSignature().getOctets());
        ContentVerifier verifier2 = verifierProv.get(signer.getAlgorithmIdentifier());
        assertFalse("tampered requestTime should fail signature verification",
            RelatedCertificateTool.verifyRequesterCertificate(tampered, verifier2));
    }

    // =====================================================================
    // Attribute wrapping
    // =====================================================================

    public void testAttributeRoundTrip()
        throws Exception
    {
        RequesterCertificate value = new RequesterCertificate(
            new IssuerAndSerialNumber(new X500Name("CN=I"), BigInteger.ONE),
            new BinaryTime(1L),
            new String[] { "https://example.com/x.cer" },
            new byte[16]);

        Attribute attr = RelatedCertificateTool.toAttribute(value);
        assertEquals(PKCSObjectIdentifiers.id_aa_relatedCertRequest, attr.getAttrType());
        assertEquals(1, attr.getAttributeValues().length);

        RequesterCertificate parsed = RelatedCertificateTool.fromAttribute(attr);
        assertTrue(Arrays.areEqual(value.getEncoded(), parsed.getEncoded()));
    }

    public void testFromAttributeRejectsWrongOid()
    {
        Attribute wrong = new Attribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword,
            new DERSet(new RequesterCertificate(
                new IssuerAndSerialNumber(new X500Name("CN=I"), BigInteger.ONE),
                new BinaryTime(1L),
                new String[] { "https://example.com/x.cer" },
                new byte[16])));
        try
        {
            RelatedCertificateTool.fromAttribute(wrong);
            fail("fromAttribute accepted wrong OID");
        }
        catch (IllegalArgumentException expected) {}
    }

    // =====================================================================
    // helpers
    // =====================================================================

    private static KeyPair ecKeyPair()
        throws Exception
    {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", BC);
        g.initialize(new ECNamedCurveGenParameterSpec("P-256"));
        return g.generateKeyPair();
    }

    private static X509CertificateHolder generateSelfSignedECCert(String dn)
        throws Exception
    {
        KeyPair kp = ecKeyPair();
        X500Name name = new X500Name(dn);
        Date notBefore = new Date(System.currentTimeMillis() - 60000L);
        Date notAfter = new Date(System.currentTimeMillis() + 24 * 60 * 60 * 1000L);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            name, BigInteger.valueOf(System.currentTimeMillis() & 0x7fffffffL),
            notBefore, notAfter, name, kp.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
            .setProvider(BC).build(kp.getPrivate());
        return builder.build(signer);
    }

    private static byte[] concat(byte[] a, byte[] b)
    {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
