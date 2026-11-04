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
import java.util.List;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkix.jcajce.PKIXCertPathReviewer;

/**
 * Which CRL the PKIXCertPathReviewer copies let decide a certificate's status, and how they read it,
 * checked against CertPathValidator("PKIX", "BC"):
 * <ul>
 * <li>only a complete CRL decides: a delta CRL lists only the changes since its base (RFC 5280 sec.
 * 5.2.4), so taking a current delta as the answer reported a certificate revoked on an expired base
 * as not revoked;</li>
 * <li>a CRL with a critical extension that cannot be processed is not used (RFC 5280 sec. 5.2);</li>
 * <li>an entry of an indirect CRL is matched on the certificate issuer as well as the serial number
 * (RFC 5280 sec. 5.3.3).</li>
 * </ul>
 */
public class PKIXCertPathReviewerCrlSelectionTest
    extends TestCase
{
    private static final long HOUR = 60 * 60 * 1000L;
    private static final long DAY = 24 * HOUR;

    private static final BigInteger EE_SERIAL = BigInteger.valueOf(7);

    private Date validationDate;

    private X500Name caDn;
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

        validationDate = new Date(System.currentTimeMillis() - 10 * DAY);

        KeyPair caKp = generateKeyPair();
        KeyPair eeKp = generateKeyPair();

        caDn = new X500Name("CN=CRL Selection Test CA");
        X500Name eeDn = new X500Name("CN=CRL Selection Test EE");

        caSigner = new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(caKp.getPrivate());

        JcaX509v3CertificateBuilder caBldr = new JcaX509v3CertificateBuilder(
            caDn, BigInteger.valueOf(1), at(-100 * DAY), at(100 * DAY), caDn, caKp.getPublic());

        caBldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
        caBldr.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        caCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(caBldr.build(caSigner));

        JcaX509v3CertificateBuilder eeBldr = new JcaX509v3CertificateBuilder(
            caDn, EE_SERIAL, at(-50 * DAY), at(50 * DAY), eeDn, eeKp.getPublic());

        eeBldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        eeBldr.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));

        eeCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(eeBldr.build(caSigner));
    }

    /**
     * The base CRL revoking the certificate has expired and a current delta against it, listing no
     * changes, is all that is current: the delta is not an answer on its own.
     */
    public void testExpiredBaseWithCurrentDeltaIsNotProofOfNonRevocation()
        throws Exception
    {
        X509CRL expiredBase = createCRL(10, null, -3 * DAY, -DAY, true, false);
        X509CRL delta = createCRL(11, BigInteger.valueOf(10), -HOUR, DAY, false, false);

        X509CRL[] crls = new X509CRL[]{ expiredBase, delta };

        // with no current complete CRL the reviewers fall back to reading the expired base, and so report its revocation
        assertEngineRejects(crls);
        assertReviewersReject(crls, "CertPathReviewer.certRevoked");
    }

    /**
     * Two deltas against a base the reviewer is not given, the earlier one expired: neither decides.
     */
    public void testDeltasWithoutBaseAreNotProofOfNonRevocation()
        throws Exception
    {
        X509CRL expiredDelta = createCRL(11, BigInteger.valueOf(10), -2 * DAY, -HOUR, false, false);
        X509CRL delta = createCRL(12, BigInteger.valueOf(10), -HOUR, DAY, false, false);

        X509CRL[] crls = new X509CRL[]{ expiredDelta, delta };

        assertEngineRejects(crls);
        assertReviewersReject(crls, "CertPathReviewer.noValidCrlFound");
    }

    /**
     * Compatibility: with a current complete CRL present, a current delta beside it changes nothing -
     * the revocation on the complete CRL is reported, and an unrevoked certificate stays valid.
     */
    public void testCurrentBaseDecidesBesideDelta()
        throws Exception
    {
        X509CRL delta = createCRL(11, BigInteger.valueOf(10), -HOUR, DAY, false, false);

        X509CRL[] revoking = new X509CRL[]{ delta, createCRL(10, null, -2 * DAY, 2 * DAY, true, false) };

        assertEngineRejects(revoking);
        assertReviewersReject(revoking, "CertPathReviewer.certRevoked");

        X509CRL[] clean = new X509CRL[]{ delta, createCRL(10, null, -2 * DAY, 2 * DAY, false, false) };

        CertPathValidator.getInstance("PKIX", "BC").validate(certPath(), params(clean));
        assertTrue("pkix reviewer rejected a current complete CRL", review(clean).isValidCertPath());
        assertTrue("legacy reviewer rejected a current complete CRL", legacyReview(clean).isValidCertPath());
    }

    /**
     * RFC 5280 sec. 5.2: a CRL carrying a critical extension that cannot be processed must not be
     * used to determine the status of a certificate.
     */
    public void testUnknownCriticalCrlExtensionIsRefused()
        throws Exception
    {
        X509CRL[] crls = new X509CRL[]{ createCRL(10, null, -2 * DAY, 2 * DAY, false, true) };

        assertEngineRejects(crls);
        assertReviewersReject(crls, "CertPathReviewer.crlUnsupportedCriticalExt");
    }

    /**
     * An indirect CRL listing another issuer's certificate with the same serial number first: the
     * entry for this certificate's issuer, which revokes it, is the one that applies.
     */
    public void testIndirectCrlEntryIsMatchedOnIssuer()
        throws Exception
    {
        X509CRL[] crls = new X509CRL[]{ createIndirectCRL(true) };

        assertEngineRejects(crls);
        assertReviewersReject(crls, "CertPathReviewer.certRevoked");
    }

    /**
     * Compatibility, and the other half: another issuer's revoked certificate with the same serial
     * number does not revoke this one.
     */
    public void testIndirectCrlOtherIssuerEntryDoesNotRevoke()
        throws Exception
    {
        X509CRL[] crls = new X509CRL[]{ createIndirectCRL(false) };

        CertPathValidator.getInstance("PKIX", "BC").validate(certPath(), params(crls));
        assertTrue("pkix reviewer applied another issuer's entry", review(crls).isValidCertPath());
        assertTrue("legacy reviewer applied another issuer's entry", legacyReview(crls).isValidCertPath());
    }

    private void assertReviewersReject(X509CRL[] crls, String errorId)
        throws Exception
    {
        PKIXCertPathReviewer reviewer = review(crls);
        assertFalse("pkix reviewer accepted the path", reviewer.isValidCertPath());
        assertTrue("pkix reviewer did not report " + errorId, hasId(reviewer.getErrors(0), errorId));
        assertFalse("pkix reviewer reported the certificate as not revoked",
            hasId(reviewer.getNotifications(0), "CertPathReviewer.notRevoked"));

        org.bouncycastle.x509.PKIXCertPathReviewer legacy = legacyReview(crls);
        assertFalse("legacy reviewer accepted the path", legacy.isValidCertPath());
        assertTrue("legacy reviewer did not report " + errorId, hasId(legacy.getErrors(0), errorId));
        assertFalse("legacy reviewer reported the certificate as not revoked",
            hasId(legacy.getNotifications(0), "CertPathReviewer.notRevoked"));
    }

    private void assertEngineRejects(X509CRL[] crls)
        throws Exception
    {
        try
        {
            CertPathValidator.getInstance("PKIX", "BC").validate(certPath(), params(crls));
            fail("CertPathValidator accepted the path");
        }
        catch (CertPathValidatorException e)
        {
            // expected
        }
    }

    private PKIXCertPathReviewer review(X509CRL[] crls)
        throws Exception
    {
        PKIXCertPathReviewer reviewer = new PKIXCertPathReviewer();

        reviewer.init(certPath(), params(crls));

        return reviewer;
    }

    private org.bouncycastle.x509.PKIXCertPathReviewer legacyReview(X509CRL[] crls)
        throws Exception
    {
        org.bouncycastle.x509.PKIXCertPathReviewer reviewer = new org.bouncycastle.x509.PKIXCertPathReviewer();

        reviewer.init(certPath(), params(crls));

        return reviewer;
    }

    private CertPath certPath()
        throws Exception
    {
        return CertificateFactory.getInstance("X.509", "BC").generateCertPath(Collections.singletonList(eeCert));
    }

    private PKIXParameters params(X509CRL[] crls)
        throws Exception
    {
        List store = new ArrayList();

        store.add(caCert);
        store.add(eeCert);
        for (int i = 0; i != crls.length; i++)
        {
            store.add(crls[i]);
        }

        PKIXParameters params = new PKIXParameters(Collections.singleton(new TrustAnchor(caCert, null)));

        params.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(store), "BC"));
        params.setRevocationEnabled(true);
        params.setDate(validationDate);

        return params;
    }

    private X509CRL createCRL(int number, BigInteger baseNumber, long thisUpdate, long nextUpdate,
                              boolean revokeEE, boolean unknownCriticalExtension)
        throws Exception
    {
        X509v2CRLBuilder crlBldr = new X509v2CRLBuilder(caDn, at(thisUpdate));

        crlBldr.setNextUpdate(at(nextUpdate));
        crlBldr.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(number)));

        if (baseNumber != null)
        {
            crlBldr.addExtension(Extension.deltaCRLIndicator, true, new CRLNumber(baseNumber));
        }
        if (unknownCriticalExtension)
        {
            crlBldr.addExtension(new ASN1ObjectIdentifier("1.3.6.1.4.1.22554.99.1"), true, DERNull.INSTANCE);
        }
        if (revokeEE)
        {
            crlBldr.addCRLEntry(EE_SERIAL, at(-5 * DAY), CRLReason.keyCompromise);
        }

        return new JcaX509CRLConverter().setProvider("BC").getCRL(crlBldr.build(caSigner));
    }

    /*
     * An indirect CRL whose first entry with the serial number belongs to another issuer, followed by an
     * entry naming the CA as certificate issuer and, when revokeEE, the CA's own entry for the serial,
     * which inherits the CA as its certificate issuer from the entry before it (RFC 5280 sec. 5.3.3).
     * The other issuer's entry is dated so that a lookup by serial number alone gets the wrong answer
     * either way: after the validation date when the certificate is revoked, before it when it is not.
     */
    private X509CRL createIndirectCRL(boolean revokeEE)
        throws Exception
    {
        X509v2CRLBuilder crlBldr = new X509v2CRLBuilder(caDn, at(-2 * DAY));

        crlBldr.setNextUpdate(at(2 * DAY));
        crlBldr.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(10)));
        crlBldr.addExtension(Extension.issuingDistributionPoint, true,
            new IssuingDistributionPoint(null, false, false, null, true, false));

        ExtensionsGenerator other = new ExtensionsGenerator();
        other.addExtension(Extension.reasonCode, false, CRLReason.lookup(CRLReason.superseded));
        other.addExtension(Extension.certificateIssuer, true,
            new GeneralNames(new GeneralName(new X500Name("CN=Other CA"))));
        crlBldr.addCRLEntry(EE_SERIAL, at(revokeEE ? 2 * DAY : -5 * DAY), other.generate());

        ExtensionsGenerator own = new ExtensionsGenerator();
        own.addExtension(Extension.certificateIssuer, true, new GeneralNames(new GeneralName(caDn)));
        crlBldr.addCRLEntry(BigInteger.valueOf(100), at(-5 * DAY), own.generate());

        if (revokeEE)
        {
            ExtensionsGenerator inherits = new ExtensionsGenerator();
            inherits.addExtension(Extension.reasonCode, false, CRLReason.lookup(CRLReason.keyCompromise));
            crlBldr.addCRLEntry(EE_SERIAL, at(-3 * DAY), inherits.generate());
        }

        return new JcaX509CRLConverter().setProvider("BC").getCRL(crlBldr.build(caSigner));
    }

    private Date at(long offset)
    {
        return new Date(validationDate.getTime() + offset);
    }

    private static KeyPair generateKeyPair()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");

        kpg.initialize(256);

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
