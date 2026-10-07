package org.bouncycastle.pkix.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.CRL;
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
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkix.jcajce.X509RevocationChecker;
import org.bouncycastle.util.CollectionStore;

/**
 * CertPath validation of a certificate listed on a CRL with a reasonCode that RFC 5280 sec. 5.3.1
 * does not define, through both the BC provider's validator and {@link X509RevocationChecker}.
 * <p>
 * The CRL entry is what revokes the certificate; an undefined reason code is processed as
 * unspecified, and is reported as given if it fits in an int. Codes 11 and 12 once collided with
 * the values the CRL status tracking used for unrevoked and undetermined, so a CRL entry carrying
 * them left the certificate unrevoked.
 * </p>
 */
public class CrlReasonCodeTest
    extends TestCase
{
    private KeyPair caKP;
    private X509Certificate caCert;
    private X509Certificate eeCert;

    public void setUp()
        throws Exception
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
        kpGen.initialize(2048);

        caKP = kpGen.generateKeyPair();
        caCert = TestUtil.makeTrustAnchor(caKP, "CN=Root,O=BC");
        eeCert = TestUtil.makeEeCertificate(false, caCert, caKP.getPrivate(), kpGen.generateKeyPair().getPublic(),
            "CN=EE");
    }

    public void testNoReasonCode()
        throws Exception
    {
        checkRevokedWithReasonCode(null, "unspecified");
    }

    public void testKeyCompromise()
        throws Exception
    {
        checkRevokedWithReasonCode(BigInteger.valueOf(1), "keyCompromise");
    }

    public void testUnused7()
        throws Exception
    {
        checkRevokedWithReasonCode(BigInteger.valueOf(7), "(unknown code: 7)");
    }

    public void testUnrevokedCollision11()
        throws Exception
    {
        checkRevokedWithReasonCode(BigInteger.valueOf(11), "(unknown code: 11)");
    }

    public void testUndeterminedCollision12()
        throws Exception
    {
        checkRevokedWithReasonCode(BigInteger.valueOf(12), "(unknown code: 12)");
    }

    public void testNegative()
        throws Exception
    {
        checkRevokedWithReasonCode(BigInteger.valueOf(-1), "(unknown code: -1)");
    }

    public void testBeyondInt()
        throws Exception
    {
        checkRevokedWithReasonCode(BigInteger.ONE.shiftLeft(40), "unspecified");
    }

    private void checkRevokedWithReasonCode(BigInteger reasonCode, String expectedReason)
        throws Exception
    {
        X509CRL crl = makeCrl(reasonCode);

        try
        {
            validate(crl, false);
            fail("provider: certificate not treated as revoked");
        }
        catch (CertPathValidatorException e)
        {
            assertEquals(0, e.getIndex());
            assertTrue(e.getMessage(), e.getMessage().startsWith("Certificate revocation after "));
            assertTrue(e.getMessage(), e.getMessage().endsWith(", reason: " + expectedReason));
        }

        try
        {
            validate(crl, true);
            fail("checker: certificate not treated as revoked");
        }
        catch (CertPathValidatorException e)
        {
            assertEquals(0, e.getIndex());
            assertTrue(e.getMessage(), e.getMessage().startsWith("certificate [issuer="));
            assertTrue(e.getMessage(), e.getMessage().indexOf(",subject=\"CN=EE\"] revoked after ") > 0);
            assertTrue(e.getMessage(), e.getMessage().endsWith(", reason: " + expectedReason));
        }
    }

    private X509CRL makeCrl(BigInteger reasonCode)
        throws Exception
    {
        long now = System.currentTimeMillis();

        X509v2CRLBuilder crlGen = new JcaX509v2CRLBuilder(caCert.getSubjectX500Principal(), new Date(now - 5 * 60 * 1000));
        crlGen.setNextUpdate(new Date(now + 60 * 60 * 1000));

        Date revocationDate = new Date(now - 60 * 1000);
        if (reasonCode == null)
        {
            crlGen.addCRLEntry(eeCert.getSerialNumber(), revocationDate, null);
        }
        else
        {
            // Built directly, since the reasonCode values of interest are not all valid CRLReasons
            ExtensionsGenerator entryExtGen = new ExtensionsGenerator();
            entryExtGen.addExtension(Extension.reasonCode, false, new ASN1Enumerated(reasonCode));
            crlGen.addCRLEntry(eeCert.getSerialNumber(), revocationDate, entryExtGen.generate());
        }

        return new JcaX509CRLConverter().setProvider("BC").getCRL(
            crlGen.build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(caKP.getPrivate())));
    }

    /**
     * The BC provider's validator processes the CRL from a certificate store; the
     * X509RevocationChecker takes it from a Store and runs as a PKIXCertPathChecker.
     */
    private void validate(X509CRL crl, boolean useChecker)
        throws Exception
    {
        Set<TrustAnchor> anchors = new HashSet<TrustAnchor>();
        anchors.add(new TrustAnchor(caCert, null));

        PKIXParameters params = new PKIXParameters(anchors);
        params.setDate(new Date());

        if (useChecker)
        {
            List<CRL> crls = new ArrayList<CRL>();
            crls.add(crl);

            params.setRevocationEnabled(false);
            params.addCertPathChecker(new X509RevocationChecker.Builder(new TrustAnchor(caCert, null))
                .addCrls(new CollectionStore<CRL>(crls))
                .build());
        }
        else
        {
            List<Object> storeContents = new ArrayList<Object>();
            storeContents.add(caCert);
            storeContents.add(eeCert);
            storeContents.add(crl);

            params.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(storeContents), "BC"));
            params.setRevocationEnabled(true);
        }

        CertPath path = CertificateFactory.getInstance("X.509", "BC").generateCertPath(Collections.singletonList(eeCert));

        CertPathValidator.getInstance("PKIX", "BC").validate(path, params);
    }
}
