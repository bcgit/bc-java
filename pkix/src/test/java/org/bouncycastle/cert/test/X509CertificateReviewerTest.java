package org.bouncycastle.cert.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Date;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509CertificateReviewer;
import org.bouncycastle.cert.X509CertificateReviewer.Finding;
import org.bouncycastle.cert.X509CertificateReviewer.Review;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class X509CertificateReviewerTest
    extends TestCase
{
    public void setUp()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testValidCertificate()
        throws Exception
    {
        X509CertificateHolder holder = makeCertificate();

        Review review = X509CertificateReviewer.reviewStructure(holder.getEncoded());

        assertTrue("expected clean review", review.isValid());
        assertTrue("expected no findings", review.getFindings().isEmpty());
        assertTrue("expected recovered certificate", review.hasCertificate());
        assertEquals(holder, review.getCertificate());
    }

    public void testGarbageBytesReportedAtEncodingStage()
        throws Exception
    {
        // SEQUENCE, definite length 5, but truncated - fails the ASN.1 decode outright
        byte[] garbage = new byte[]{ (byte)0x30, (byte)0x05, (byte)0x02, (byte)0x01 };

        Review review = X509CertificateReviewer.reviewStructure(garbage);

        assertFalse(review.isValid());
        assertFalse(review.hasCertificate());
        assertEquals(1, review.getFindings().size());
        assertEquals("encoding", ((Finding)review.getFindings().get(0)).getLocation());
    }

    public void testWrongSequenceSize()
        throws Exception
    {
        ASN1Sequence full = ASN1Sequence.getInstance(makeCertificate().toASN1Structure().toASN1Primitive());

        // a two-element SEQUENCE is not a certificate
        ASN1Sequence twoElements = new DERSequence(new ASN1Encodable[]{
            full.getObjectAt(0), full.getObjectAt(1) });

        Review review = X509CertificateReviewer.reviewStructure(twoElements);

        assertFalse(review.isValid());
        assertFalse(review.hasCertificate());
        assertEquals(1, review.getFindings().size());
        Finding f = (Finding)review.getFindings().get(0);
        assertEquals("certificate", f.getLocation());
        assertTrue(f.getMessage().startsWith("sequence wrong size for a certificate"));
    }

    public void testIndependentComponentProbing()
        throws Exception
    {
        ASN1Sequence full = ASN1Sequence.getInstance(makeCertificate().toASN1Structure().toASN1Primitive());

        // valid tbsCertificate, but a bogus signatureAlgorithm AND a bogus signature:
        // both sibling problems must be reported, and the tbsCertificate must not be flagged.
        ASN1Sequence broken = new DERSequence(new ASN1Encodable[]{
            full.getObjectAt(0),        // good
            new ASN1Integer(1),         // signatureAlgorithm is not a SEQUENCE
            new ASN1Integer(2) });      // signature is not a BIT STRING

        Review review = X509CertificateReviewer.reviewStructure(broken);

        assertFalse(review.isValid());
        assertFalse(review.hasCertificate());

        List findings = review.getFindings();
        assertEquals(2, findings.size());
        assertEquals("signatureAlgorithm", ((Finding)findings.get(0)).getLocation());
        assertEquals("signature", ((Finding)findings.get(1)).getLocation());
        for (int i = 0; i != findings.size(); i++)
        {
            assertFalse("tbsCertificate should have parsed cleanly",
                "tbsCertificate".equals(((Finding)findings.get(i)).getLocation()));
        }
    }

    public void testEnumeratesMultipleTbsProblems()
        throws Exception
    {
        ASN1Sequence full = ASN1Sequence.getInstance(makeCertificate().toASN1Structure().toASN1Primitive());
        ASN1Sequence tbs = ASN1Sequence.getInstance(full.getObjectAt(0));

        // rebuild the tbsCertificate with TWO independent semantic defects: an unrecognised
        // version AND an empty issuer DN. The strict path throws on the first; the reviewer
        // (via the shared collect-all parse) must report both.
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERTaggedObject(true, 0, new ASN1Integer(5)));   // version not 0/1/2
        v.add(tbs.getObjectAt(1));                                  // serialNumber (good)
        v.add(tbs.getObjectAt(2));                                  // signature alg (good)
        v.add(new DERSequence());                                  // issuer: empty Name
        v.add(tbs.getObjectAt(4));                                  // validity (good)
        v.add(tbs.getObjectAt(5));                                  // subject (good)
        v.add(tbs.getObjectAt(6));                                  // subjectPublicKeyInfo (good)
        ASN1Sequence badTbs = new DERSequence(v);

        ASN1Sequence badCert = new DERSequence(new ASN1Encodable[]{
            badTbs, full.getObjectAt(1), full.getObjectAt(2) });

        Review review = X509CertificateReviewer.reviewStructure(badCert);

        assertFalse(review.isValid());
        assertFalse(review.hasCertificate());

        boolean sawVersion = false;
        boolean sawEmptyIssuer = false;
        List findings = review.getFindings();
        for (int i = 0; i != findings.size(); i++)
        {
            Finding f = (Finding)findings.get(i);
            assertEquals("tbsCertificate", f.getLocation());
            // each collected problem now carries the exception the strict path would have thrown
            assertNotNull("finding should carry the originating exception", f.getCause());
            assertTrue(f.getCause() instanceof IllegalArgumentException);
            assertEquals(f.getMessage(), f.getCause().getMessage());
            if ("version number not recognised".equals(f.getMessage()))
            {
                sawVersion = true;
            }
            if ("certificate issuer is an empty distinguished name".equals(f.getMessage()))
            {
                sawEmptyIssuer = true;
            }
        }
        assertTrue("expected the bad-version finding", sawVersion);
        assertTrue("expected the empty-issuer finding", sawEmptyIssuer);
    }

    public void testExpandsRepeatedExtensionIntoPerExtensionFindings()
        throws Exception
    {
        X509CertificateHolder holder = makeCertificateWithExtension();
        ASN1Sequence full = ASN1Sequence.getInstance(holder.toASN1Structure().toASN1Primitive());
        ASN1Sequence tbs = ASN1Sequence.getInstance(full.getObjectAt(0));

        // the extensions are the trailing [3] EXPLICIT element; duplicate the first extension
        // so the extension set carries a repeated OID.
        ASN1TaggedObject extTagged = (ASN1TaggedObject)tbs.getObjectAt(tbs.size() - 1);
        assertEquals(3, extTagged.getTagNo());
        ASN1Sequence exts = ASN1Sequence.getInstance(extTagged, true);
        ASN1Encodable firstExt = exts.getObjectAt(0);
        ASN1Sequence duplicated = new DERSequence(new ASN1Encodable[]{ firstExt, firstExt });

        ASN1EncodableVector tbsv = new ASN1EncodableVector();
        for (int i = 0; i < tbs.size() - 1; i++)
        {
            tbsv.add(tbs.getObjectAt(i));
        }
        tbsv.add(new DERTaggedObject(true, 3, duplicated));
        ASN1Sequence badCert = new DERSequence(new ASN1Encodable[]{
            new DERSequence(tbsv), full.getObjectAt(1), full.getObjectAt(2) });

        Review review = X509CertificateReviewer.reviewStructure(badCert);

        assertFalse(review.isValid());
        assertFalse(review.hasCertificate());

        // the aggregate from the extensions sub-parse is expanded into per-extension findings
        List findings = review.getFindings();
        assertEquals(1, findings.size());
        Finding f = (Finding)findings.get(0);
        assertEquals("tbsCertificate.extensions", f.getLocation());
        assertTrue(f.getMessage().startsWith("repeated extension found:"));
        assertNotNull(f.getCause());
        assertTrue(f.getCause() instanceof IllegalArgumentException);
    }

    private static X509CertificateHolder makeCertificateWithExtension()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        long now = System.currentTimeMillis();
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            new X500Principal("CN=Test"),
            BigInteger.valueOf(1),
            new Date(now - 60000L),
            new Date(now + 365L * 24 * 60 * 60 * 1000),
            new X500Principal("CN=Test"),
            kp.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(kp.getPrivate());
        return builder.build(signer);
    }

    private static X509CertificateHolder makeCertificate()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        long now = System.currentTimeMillis();
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            new X500Principal("CN=Test"),
            BigInteger.valueOf(1),
            new Date(now - 60000L),
            new Date(now + 365L * 24 * 60 * 60 * 1000),
            new X500Principal("CN=Test"),
            kp.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(kp.getPrivate());
        return builder.build(signer);
    }
}
