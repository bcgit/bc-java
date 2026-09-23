package org.bouncycastle.pkix.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import junit.framework.TestCase;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkix.jcajce.PKIXCertPathReviewer;

/**
 * RFC 5280 sec. 6.3.3 decides which CRLs say anything about the certificate under test: (b)(2)(i)
 * requires a name in the CRL's issuing distribution point to match one in the certificate's
 * distribution point, and (d) intersects the revocation reasons the two of them assert. Both
 * PKIXCertPathReviewer copies applied neither, taking the first date-valid CRL from the certificate's
 * issuer as an answer, so a CA-signed CRL with no entries and a scope covering some other partition
 * came back as proof of non-revocation - with an empty error list, while CertPathValidator("PKIX")
 * rejected the identical chain against the identical trust anchor. Where the reviewer makes the trust
 * decision, as SignedMailValidator does with the CRLs carried inside a signed message, that turns a
 * revoked certificate into a valid one; and the decoy also suppressed the CRL distribution point
 * fetch that would otherwise have found the revocation.
 */
public class PKIXCertPathReviewerCrlScopeTest
    extends TestCase
{
    private static final String MINE = "http://crl.example.com/mine.crl";
    private static final String OTHER = "http://crl.example.com/other.crl";

    private static final BigInteger EE_SERIAL = BigInteger.valueOf(2);

    private Date past;
    private Date future;

    private X509Certificate caCert;
    private X509Certificate eeCert;
    private ContentSigner caSigner;

    public void setUp()
        throws Exception
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        past = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000L);
        future = new Date(System.currentTimeMillis() + 24 * 60 * 60 * 1000L);

        KeyPair caKp = generateKeyPair();
        KeyPair eeKp = generateKeyPair();

        X500Name caDn = new X500Name("CN=CRL Scope Test CA");
        X500Name eeDn = new X500Name("CN=CRL Scope Test EE");

        caSigner = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(caKp.getPrivate());

        JcaX509v3CertificateBuilder caBldr = new JcaX509v3CertificateBuilder(
            caDn, BigInteger.valueOf(1), past, future, caDn, caKp.getPublic());

        caBldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
        caBldr.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        caCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(caBldr.build(caSigner));

        JcaX509v3CertificateBuilder eeBldr = new JcaX509v3CertificateBuilder(
            caDn, EE_SERIAL, past, future, eeDn, eeKp.getPublic());

        eeBldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        eeBldr.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        eeBldr.addExtension(Extension.cRLDistributionPoints, false,
            new CRLDistPoint(new DistributionPoint[]{ new DistributionPoint(uriName(MINE), null, null) }));

        eeCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(eeBldr.build(caSigner));
    }

    /**
     * The certificate's distribution point names mine.crl; a CRL scoped to some other partition is
     * not an answer about this certificate, whether or not it carries an entry for it.
     */
    public void testOutOfScopeDistributionPointIsNotProofOfNonRevocation()
        throws Exception
    {
        X509CRL decoy = createCRL(new IssuingDistributionPoint(uriName(OTHER), false, false), false);

        assertEngineRejects(decoy);
        assertReviewersReject(decoy);
    }

    /**
     * A CRL covering only certificateHold cannot say that a certificate was not revoked for key
     * compromise: sec. 6.3.3 (d) leaves the remaining reasons unanswered.
     */
    public void testReasonPartitionedCrlIsNotProofOfNonRevocation()
        throws Exception
    {
        X509CRL decoy = createCRL(new IssuingDistributionPoint(uriName(MINE), false, false,
            new ReasonFlags(ReasonFlags.certificateHold), false, false), false);

        assertEngineRejects(decoy);
        assertReviewersReject(decoy);
    }

    /**
     * Compatibility: a CRL whose issuing distribution point names the certificate's own distribution
     * point still answers for it, and the answer is still "not revoked" when it carries no entry.
     */
    public void testInScopeCrlIsAccepted()
        throws Exception
    {
        X509CRL inScope = createCRL(new IssuingDistributionPoint(uriName(MINE), false, false), false);

        CertPathValidator.getInstance("PKIX", "BC").validate(certPath(), params(inScope));

        assertTrue("pkix reviewer rejected an in-scope CRL", review(inScope).isValidCertPath());
        assertTrue("legacy reviewer rejected an in-scope CRL", legacyReview(inScope).isValidCertPath());
    }

    /**
     * Compatibility: a CRL with no issuing distribution point covers everything its issuer issues.
     */
    public void testCrlWithoutIssuingDistributionPointIsAccepted()
        throws Exception
    {
        X509CRL unscoped = createCRL(null, false);

        CertPathValidator.getInstance("PKIX", "BC").validate(certPath(), params(unscoped));

        assertTrue("pkix reviewer rejected a CRL with no IDP", review(unscoped).isValidCertPath());
        assertTrue("legacy reviewer rejected a CRL with no IDP", legacyReview(unscoped).isValidCertPath());
    }

    /**
     * Compatibility: the validation engine falls back to a distribution point naming the certificate
     * issuer for CRLs the certificate's own distribution points do not name, so a CRL scoped to the
     * issuer name has to keep working here too.
     */
    public void testCrlScopedToIssuerNameIsAccepted()
        throws Exception
    {
        X500Name issuer = X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded());
        DistributionPointName dpName = new DistributionPointName(0,
            new GeneralNames(new GeneralName(GeneralName.directoryName, issuer)));

        X509CRL issuerScoped = createCRL(new IssuingDistributionPoint(dpName, false, false), false);

        CertPathValidator.getInstance("PKIX", "BC").validate(certPath(), params(issuerScoped));

        assertTrue("pkix reviewer rejected an issuer-scoped CRL", review(issuerScoped).isValidCertPath());
        assertTrue("legacy reviewer rejected an issuer-scoped CRL", legacyReview(issuerScoped).isValidCertPath());
    }

    /**
     * Compatibility: an in-scope CRL which does carry the certificate is still reported as a
     * revocation rather than swallowed by the scope test.
     */
    public void testRevocationIsStillReported()
        throws Exception
    {
        X509CRL revoking = createCRL(new IssuingDistributionPoint(uriName(MINE), false, false), true);

        assertEngineRejects(revoking);

        PKIXCertPathReviewer reviewer = review(revoking);
        assertFalse("pkix reviewer accepted a revoked certificate", reviewer.isValidCertPath());
        assertTrue("pkix reviewer did not report the revocation",
            hasId(reviewer.getErrors(0), "CertPathReviewer.certRevoked"));

        org.bouncycastle.x509.PKIXCertPathReviewer legacy = legacyReview(revoking);
        assertFalse("legacy reviewer accepted a revoked certificate", legacy.isValidCertPath());
        assertTrue("legacy reviewer did not report the revocation",
            hasId(legacy.getErrors(0), "CertPathReviewer.certRevoked"));
    }

    private void assertReviewersReject(X509CRL crl)
        throws Exception
    {
        PKIXCertPathReviewer reviewer = review(crl);
        assertFalse("pkix reviewer took an out-of-scope CRL as proof of non-revocation",
            reviewer.isValidCertPath());
        assertTrue("pkix reviewer did not report the missing CRL",
            hasId(reviewer.getErrors(0), "CertPathReviewer.noValidCrlFound"));
        assertFalse("pkix reviewer reported an out-of-scope CRL as not revoked",
            hasId(reviewer.getNotifications(0), "CertPathReviewer.notRevoked"));

        org.bouncycastle.x509.PKIXCertPathReviewer legacy = legacyReview(crl);
        assertFalse("legacy reviewer took an out-of-scope CRL as proof of non-revocation",
            legacy.isValidCertPath());
        assertTrue("legacy reviewer did not report the missing CRL",
            hasId(legacy.getErrors(0), "CertPathReviewer.noValidCrlFound"));
        assertFalse("legacy reviewer reported an out-of-scope CRL as not revoked",
            hasId(legacy.getNotifications(0), "CertPathReviewer.notRevoked"));
    }

    /**
     * The validation engine is the ground truth here, and its rejection has to arrive as a
     * CertPathValidatorException: with no candidate CRL contributing new reasons, checkCRL had
     * nothing recorded to throw and let a NullPointerException out instead.
     */
    private void assertEngineRejects(X509CRL crl)
        throws Exception
    {
        try
        {
            CertPathValidator.getInstance("PKIX", "BC").validate(certPath(), params(crl));
            fail("CertPathValidator accepted a certificate with no CRL in scope");
        }
        catch (CertPathValidatorException e)
        {
            // expected
        }
    }

    private PKIXCertPathReviewer review(X509CRL crl)
        throws Exception
    {
        PKIXCertPathReviewer reviewer = new PKIXCertPathReviewer();

        reviewer.init(certPath(), params(crl));

        return reviewer;
    }

    private org.bouncycastle.x509.PKIXCertPathReviewer legacyReview(X509CRL crl)
        throws Exception
    {
        org.bouncycastle.x509.PKIXCertPathReviewer reviewer = new org.bouncycastle.x509.PKIXCertPathReviewer();

        reviewer.init(certPath(), params(crl));

        return reviewer;
    }

    private CertPath certPath()
        throws Exception
    {
        return CertificateFactory.getInstance("X.509", "BC").generateCertPath(Collections.singletonList(eeCert));
    }

    private PKIXParameters params(X509CRL crl)
        throws Exception
    {
        List store = new ArrayList();

        store.add(caCert);
        store.add(eeCert);
        store.add(crl);

        Set trust = new HashSet();

        trust.add(new TrustAnchor(caCert, null));

        PKIXParameters params = new PKIXParameters(trust);

        params.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(store), "BC"));
        params.setRevocationEnabled(true);

        return params;
    }

    private X509CRL createCRL(IssuingDistributionPoint idp, boolean revokeEE)
        throws Exception
    {
        X509v2CRLBuilder crlBldr = new JcaX509v2CRLBuilder(caCert, past);

        crlBldr.setNextUpdate(future);

        if (revokeEE)
        {
            crlBldr.addCRLEntry(EE_SERIAL, past, CRLReason.keyCompromise);
        }

        if (idp != null)
        {
            crlBldr.addExtension(Extension.issuingDistributionPoint, true, idp);
        }

        return new JcaX509CRLConverter().setProvider("BC").getCRL(crlBldr.build(caSigner));
    }

    private static DistributionPointName uriName(String url)
    {
        return new DistributionPointName(0,
            new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, url)));
    }

    private static KeyPair generateKeyPair()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");

        kpg.initialize(2048);

        return kpg.generateKeyPair();
    }

    private static boolean hasId(List bundles, String id)
    {
        for (int i = 0; i != bundles.size(); i++)
        {
            // the two reviewer copies use different ErrorBundle forks
            Object n = bundles.get(i);
            String nId = (n instanceof org.bouncycastle.pkix.util.ErrorBundle)
                ? ((org.bouncycastle.pkix.util.ErrorBundle)n).getId()
                : ((org.bouncycastle.i18n.ErrorBundle)n).getId();
            if (id.equals(nId))
            {
                return true;
            }
        }

        return false;
    }
}
