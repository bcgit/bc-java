package org.bouncycastle.pkix.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkix.jcajce.PKIXCertPathReviewer;

/**
 * RFC 5280 sec. 6.1.2 (b) and (c): the name constraints carried by a TrustAnchor seed the
 * permitted and excluded subtrees, so a chain naming something outside them must not validate.
 */
public class TrustAnchorNameConstraintsTest
    extends TestCase
{
    private static final X500Name ROOT_NAME = new X500Name("C=AU, O=Corp, CN=Root");
    private static final X500Name INT_NAME = new X500Name("C=AU, O=Corp, CN=Partner CA");

    private KeyPair rootKp;
    private KeyPair intKp;
    private X509Certificate root;
    private X509Certificate intermediate;

    private long serial = 1;

    public void setUp()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
        kpg.initialize(256);

        rootKp = kpg.generateKeyPair();
        intKp = kpg.generateKeyPair();

        root = createCert(ROOT_NAME, rootKp.getPrivate(), ROOT_NAME, rootKp, true, null);
        intermediate = createCert(ROOT_NAME, rootKp.getPrivate(), INT_NAME, intKp, true, null);
    }

    public void testNoAnchorConstraints()
        throws Exception
    {
        X509Certificate leaf = createLeaf(new X500Name("CN=www.bank.example, O=Bank, C=AU"), "www.bank.example");

        checkAccepted(new TrustAnchor(root, null), leaf);
    }

    public void testPermittedDNSNameInside()
        throws Exception
    {
        byte[] nc = encode(new NameConstraints(
            new GeneralSubtree[]{ new GeneralSubtree(new GeneralName(GeneralName.dNSName, "corp.example")) }, null));
        X509Certificate leaf = createLeaf(new X500Name("CN=www.corp.example, O=Corp, C=AU"), "www.corp.example");

        checkAccepted(new TrustAnchor(root, nc), leaf);
        checkAccepted(new TrustAnchor(ROOT_NAME.toString(), rootKp.getPublic(), nc), leaf, false);
    }

    public void testPermittedDNSNameOutside()
        throws Exception
    {
        byte[] nc = encode(new NameConstraints(
            new GeneralSubtree[]{ new GeneralSubtree(new GeneralName(GeneralName.dNSName, "corp.example")) }, null));
        X509Certificate leaf = createLeaf(new X500Name("CN=www.bank.example, O=Corp, C=AU"), "www.bank.example");

        checkRejected(new TrustAnchor(root, nc), leaf, "Subtree check for certificate subject alternative name failed.");
        checkRejected(new TrustAnchor(ROOT_NAME.toString(), rootKp.getPublic(), nc), leaf,
            "Subtree check for certificate subject alternative name failed.", false);
    }

    public void testExcludedDNSName()
        throws Exception
    {
        byte[] nc = encode(new NameConstraints(null,
            new GeneralSubtree[]{ new GeneralSubtree(new GeneralName(GeneralName.dNSName, "bank.example")) }));

        checkRejected(new TrustAnchor(root, nc),
            createLeaf(new X500Name("CN=www.bank.example, O=Corp, C=AU"), "www.bank.example"),
            "Subtree check for certificate subject alternative name failed.");
        checkAccepted(new TrustAnchor(root, nc),
            createLeaf(new X500Name("CN=www.corp.example, O=Corp, C=AU"), "www.corp.example"));
    }

    public void testPermittedDirectoryName()
        throws Exception
    {
        byte[] nc = encode(new NameConstraints(
            new GeneralSubtree[]{ new GeneralSubtree(new GeneralName(new X500Name("C=AU, O=Corp"))) }, null));

        checkRejected(new TrustAnchor(root, nc),
            createLeaf(new X500Name("C=AU, O=Bank, CN=www.bank.example"), null),
            "Subtree check for certificate subject failed.");
        checkAccepted(new TrustAnchor(root, nc),
            createLeaf(new X500Name("C=AU, O=Corp, CN=www.corp.example"), null));
    }

    private void checkAccepted(TrustAnchor anchor, X509Certificate leaf)
        throws Exception
    {
        checkAccepted(anchor, leaf, true);
    }

    // the reviewers only locate certificate trust anchors, so name and key anchors go to the validator and builder alone
    private void checkAccepted(TrustAnchor anchor, X509Certificate leaf, boolean withReviewers)
        throws Exception
    {
        CertPath path = createPath(leaf);

        CertPathValidator validator = CertPathValidator.getInstance("PKIX", "BC");
        validator.validate(path, createParams(anchor));

        PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult)CertPathBuilder.getInstance("PKIX", "BC")
            .build(createBuilderParams(anchor, leaf));
        assertEquals(2, result.getCertPath().getCertificates().size());

        if (!withReviewers)
        {
            return;
        }

        PKIXCertPathReviewer reviewer = new PKIXCertPathReviewer(path, createParams(anchor));
        assertTrue(reviewer.isValidCertPath());

        org.bouncycastle.x509.PKIXCertPathReviewer legacyReviewer =
            new org.bouncycastle.x509.PKIXCertPathReviewer(path, createParams(anchor));
        assertTrue(legacyReviewer.isValidCertPath());
    }

    private void checkRejected(TrustAnchor anchor, X509Certificate leaf, String message)
        throws Exception
    {
        checkRejected(anchor, leaf, message, true);
    }

    private void checkRejected(TrustAnchor anchor, X509Certificate leaf, String message, boolean withReviewers)
        throws Exception
    {
        CertPath path = createPath(leaf);

        try
        {
            CertPathValidator.getInstance("PKIX", "BC").validate(path, createParams(anchor));
            fail("validator accepted a path outside the trust anchor's name constraints");
        }
        catch (CertPathValidatorException e)
        {
            assertEquals(message, e.getMessage());
        }

        try
        {
            CertPathBuilder.getInstance("PKIX", "BC").build(createBuilderParams(anchor, leaf));
            fail("builder accepted a path outside the trust anchor's name constraints");
        }
        catch (CertPathBuilderException e)
        {
            // expected
        }

        if (!withReviewers)
        {
            return;
        }

        PKIXCertPathReviewer reviewer = new PKIXCertPathReviewer(path, createParams(anchor));
        assertFalse(reviewer.isValidCertPath());

        org.bouncycastle.x509.PKIXCertPathReviewer legacyReviewer =
            new org.bouncycastle.x509.PKIXCertPathReviewer(path, createParams(anchor));
        assertFalse(legacyReviewer.isValidCertPath());
    }

    private PKIXParameters createParams(TrustAnchor anchor)
        throws Exception
    {
        PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
        params.setRevocationEnabled(false);
        return params;
    }

    private PKIXBuilderParameters createBuilderParams(TrustAnchor anchor, X509Certificate leaf)
        throws Exception
    {
        List certs = new ArrayList();
        certs.add(intermediate);
        certs.add(leaf);

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(leaf);

        PKIXBuilderParameters params = new PKIXBuilderParameters(Collections.singleton(anchor), selector);
        params.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(certs), "BC"));
        params.setRevocationEnabled(false);
        return params;
    }

    private CertPath createPath(X509Certificate leaf)
        throws Exception
    {
        List certs = new ArrayList();
        certs.add(leaf);
        certs.add(intermediate);

        return CertificateFactory.getInstance("X.509", "BC").generateCertPath(certs);
    }

    private X509Certificate createLeaf(X500Name subject, String dnsName)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
        kpg.initialize(256);

        return createCert(INT_NAME, intKp.getPrivate(), subject, kpg.generateKeyPair(), false, dnsName);
    }

    private X509Certificate createCert(X500Name issuer, PrivateKey issuerKey, X500Name subject, KeyPair subjectKp,
                                       boolean isCA, String dnsName)
        throws Exception
    {
        long now = System.currentTimeMillis();

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuer, BigInteger.valueOf(serial++),
            new Date(now - 60000L), new Date(now + 24L * 60 * 60 * 1000), subject, subjectKp.getPublic());

        if (isCA)
        {
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        }
        else
        {
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        }

        if (dnsName != null)
        {
            builder.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.dNSName, dnsName)));
        }

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(issuerKey);

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
    }

    private static byte[] encode(NameConstraints nc)
        throws Exception
    {
        return nc.getEncoded(ASN1Encoding.DER);
    }
}
