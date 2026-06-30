package org.bouncycastle.pkix.test;

import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathValidator;
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
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import java.io.ByteArrayInputStream;

import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkix.jcajce.PKIXCertPathReviewer;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.encoders.Base64;

public class CheckNameConstraintsTest 
    extends TestCase
{
    // github #2320 fixtures: the issuing CA
    private static final byte[] NC_NON_CA_ROOT = Base64.decode(
        "MIIFpzCCA4+gAwIBAgIBATANBgkqhkiG9w0BAQsFADBGMQswCQYDVQQGEwJVTjEM"
            + "MAoGA1UECAwDTllTMQ0wCwYDVQQKDARVTkdBMQ0wCwYDVQQLDARVTlNDMQswCQYD"
            + "VQQDDAJEVDAgGA8yMDE5MDYxOTA4NTU1OVoXDTMxMDEyMzA5MjY0MVowRjELMAkG"
            + "A1UEBhMCVU4xDDAKBgNVBAgMA05ZUzENMAsGA1UECgwEVU5HQTENMAsGA1UECwwE"
            + "VU5TQzELMAkGA1UEAwwCRFQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC"
            + "AQDUH4HOaQGve0tFgKtsN0bmCvKJZOmTBL6EdJhfGJejBoiamGY6e6wy9tfpQjdK"
            + "ze/tR5k1HREs0Tj/fNqU8zD5bmrdXOkYcgOylTAOPVCng7zKTa0Lx7k6dvuNNbmU"
            + "hczvD5Yld+FHlZjXQxyRHq7lrbJCWwe6WAkU0lSleSpoYU4jQ8tQJ/9j4XJG9YRO"
            + "JMXKf+rgAiBe4dImFZJnCV/rlJXJOD2oqxlgouLcKqoPiV2oR2Tov8X32nmy2UCi"
            + "bcqCtDbXS8JbY5eV1YuP/8OF8QGd6wC9fRXtxLMFXAnsWr+gXrgP3/qHH5y1Rz+C"
            + "1oiqnugDDUNHbjAT8Bbw76yZqtWPS0LVPa6O+53UxNE+eLLesSP4jktByK9OjCeW"
            + "q+DLDnhIzllpEosezBFhEERuiOzfmsd2e/LSe4NB3ZVQAsvuggEAtl4pYbWDt9ht"
            + "pg0SzPfkURY+UuZuM2XidFoh58Wvn1sSVzWtx2OVisNw2UhqnQHAQ3Rh31jZgcWq"
            + "5QxoTNwbztK+9nUQzHfwbmFudThta4H3hCKkxSFXaqcb8YryJXQCmA0rDFapr9b4"
            + "syS5cmrVw27FJytuvZ3oOiIeBdTmc/0ByQPjGPGfGmY/2Ed/OdVQEaKEpvK6bHpF"
            + "wfNN+FNseH9LHmlI8x936givvqOONCFjUbhUoGa9TenpXQIDAQABo4GdMIGaMFgG"
            + "A1UdIwRRME+hSqRIMEYxCzAJBgNVBAYTAlVOMQwwCgYDVQQIDANOWVMxDTALBgNV"
            + "BAoMBFVOR0ExDTALBgNVBAsMBFVOU0MxCzAJBgNVBAMMAkRUggEBMB0GA1UdDgQW"
            + "BBTq053y+hIVHWuQAR8d2yd/r9Fl1zAOBgNVHQ8BAf8EBAMCAgQwDwYDVR0TAQH/"
            + "BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAgEADDOWCLOUbicW+AiZZWrp67gwHBmo"
            + "eyTa4F3A10nMgcLHfR2DEqte3xXN1BiBfY1V/Ra4b21/hRRllhX8nzp0+/CrajJS"
            + "9z8Vzp0Hldm5Wm65swPfSFfToR5pToXIJATjRa5WZu+HlcDIKyFUxquErCwYnBHH"
            + "5pLujFkj98BRmJsSWHGbqfldOYO/PjVpy0ljgLs1Xl6jNJS3WLFKeezVlRbeILqC"
            + "IcTuOtI7D/4tDevvnzcugfuphAglvc12/E8GHRX87EPat5JU+bAo+OsQmuoMpjpe"
            + "30/Wb1wiVvm5/D2tvxxmW3pvIGfXA/4hcdZJ8FCO8gnbFYt2bum3UqEKmk3j/mBK"
            + "uDuv/M8UOSA37CfQgQAhsaohYzRvc5+PusOMJPSL03+D9j+U5jT1KJ6eZxfFBdnD"
            + "1bx4rU77ZkA0W3rfd0z9zS8SXOD2wuvra87gBWCG0d3m4QsYgAze8d9Ec4NkC+oU"
            + "yzBzogx0p7+JApIt+wz0mBYUip5X/cGCRcxp8Zs52Rt0VpmFuDxLo3Z5Q5xjz41V"
            + "N5K/iEempbsGpCwwU6id/w/sBHG8fP9XzlGXA2ZR/aXPGOVHB6f0LzTgu2KLKosJ"
            + "JRUkyGS7kAJfFAbaR6ZQbzLnrK7lC9dSWPEiw5wVP3dUUrmrGVZer/DWJyeFJbxy"
            + "F0PDy/8R70rVDCA=");

    // github #2320 fixtures: a CA:FALSE end-entity cert carrying critical nameConstraints and policyConstraints extensions
    private static final byte[] NC_NON_CA_EE = Base64.decode(
        "MIIGIDCCBAigAwIBAgIBAjANBgkqhkiG9w0BAQsFADBGMQswCQYDVQQGEwJVTjEM"
            + "MAoGA1UECAwDTllTMQ0wCwYDVQQKDARVTkdBMQ0wCwYDVQQLDARVTlNDMQswCQYD"
            + "VQQDDAJEVDAiGA8yMDE5MDYyNTE5NTUxOVoYDzIwMzAwMTIzMDkyNjQxWjBSMQsw"
            + "CQYDVQQGEwJVTjEMMAoGA1UECAwDTllTMQ0wCwYDVQQKDARVTkdBMRMwEQYDVQQL"
            + "DApVTlNDLXBlYWNlMREwDwYDVQQDDAhEVC1wZWFjZTCCAiIwDQYJKoZIhvcNAQEB"
            + "BQADggIPADCCAgoCggIBANS7iw9O+XINCBnAJqToCC8zjmywqd1C/M0oAopFzqwP"
            + "hHeIh4FFE4FOydverb2fCGZgvqYBj92V+erzWnUhnRNCGGSxcUpbab5hc2KBHoXk"
            + "leVZFKJtgit0vT+Vxgx6cYpr08UBTY7FGPFWU49fFfcw/mQHMW/vjrlRjH/bGMMg"
            + "16dsFNYgZMO6esqgP54GQekiXyIzn6WRq7aFluB69hXpEFiSPph9MPHFWJIgCdUv"
            + "3RJnzQy+L8hkEL5eQGIKl5GZNxzJirCd8LNcWLcbNPe8TAQMWQqNzsmGzyl1n33Z"
            + "IZPs8M5M3R4DKtZsO12WzA5g+rk8MuAnoUxfBYKU9U9FXMcT5XDXYokbGbhaa8VA"
            + "JAfUFvYpiZIC8kmVRq4YOOKmWTKWdOQ8II9Jwd6dwABCTiaJ32/C6tMaLeb4uFbJ"
            + "czBoQY1Jkawbb+XwvfRVkrpU9bhY3tmqIrcQrsCNuvRaXoy9r0vBlgwATpFFhqJ6"
            + "gpAwhG5xj6CgJ2UyJ1Ko1YUu8or0FXaG0RncuIRgizPU7JENr+c6nHlfH2Y7hqlH"
            + "Ysp2zew4+8j1s/SeZRIKf64lJVRZ97UCymTUm8PyDzv+gK9/NALI2n/D9pL9bBOq"
            + "uTVBFX4pc3qEYutbupqJ9YS1vw48rObP9WFhl+xkybh4q6GT+gX8KBfLqnVbQW2X"
            + "AgMBAAGjggEHMIIBAzAfBgNVHSMEGDAWgBTq053y+hIVHWuQAR8d2yd/r9Fl1zAd"
            + "BgNVHQ4EFgQUvJOnwU1RobEeXcnBkerbW1PVvFgwDAYDVR0TAQH/BAIwADCBngYD"
            + "VR0eAQH/BIGTMIGQoDcwCYEHYUBiLmNvbTALggl3d3cuYy5jb20wCocI29oSEv//"
            + "//8wEaQPMA0xCzAJBgNVBAYTAlVOoVUwCYEHY0BkLmNvbTALggl3d3cuZi5jb20w"
            + "IocgIAECUFgdACLsoNuNa4OfWf////////////////////8wF6QVMBMxETAPBgNV"
            + "BAgMCFNoYW5kb25nMBIGA1UdJAEB/wQIMAaAAQGBAQIwDQYJKoZIhvcNAQELBQAD"
            + "ggIBADQ6dAcn8AGPDQZd6OMzVI0J2HDO+lowKSXBH3x7tNljh4G2pu+je9+H4u0R"
            + "2AGdIg/+AdeYq6YjwhxTPv8GNdiAzKZrva6a6OfVn0ZRRXVjXFylaNRhs+o77DX5"
            + "fi4ZW3AJh/jd93GD5C/NXGivKiB4IxKLfrp58JX2UfE/1QnGUprXkD6jxX/f49GI"
            + "pMg/8JN66fwFvX71hiB2KoyGhfEOYyxFAG9qb1nvLx/7T4u9jjnxcNpDG/y9VWVd"
            + "9Dpn7edOgFn62vJkDrpwGtIO9eckwJspell7PXeT1rFf6TihEu6592an/WEE20vH"
            + "Oo0qgkHGPdDJEVVS8BGI/FpORB5yDDH4bFDpAku4ZTaH4QE6wKsVOx86PwdK0NpU"
            + "3VR+bjcR/WgfRxdM8+8BgSbKatxXnFD25u1z1U0vPRKsm0zG6FXTyLfH8tB4DqoP"
            + "ONrvr4U4K6N+FG5ieHP1cyvRF0n8imwppotTzHTXkWwTvczk0f4bPxJ1KnW8LLVH"
            + "qBUlBBySRvA3BsYaft12iWDxFhR+FwCsnjgHxxgXzCj99RJLf4JJLPDqUARXKJoh"
            + "lu69peWzuTiduHqLUdrmUO/ObsUINMMcjcyrOTpiCMXJqZMhMqgzouf77ib/DAii"
            + "4GqxNtfCa95aoB1Cn8zh7tPARYeQD5gN2L8cZkOVmd+YKxvW");

    public void testPKIXCertPathReviewer()
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        X509Certificate root = (X509Certificate) cf.generateCertificate(TestResourceFinder.findTestResource("pkix", "mal-root.crt"));
        X509Certificate ca1 = (X509Certificate) cf.generateCertificate(TestResourceFinder.findTestResource("pkix", "mal-ca1.crt"));
        X509Certificate ca2 = (X509Certificate) cf.generateCertificate(TestResourceFinder.findTestResource("pkix", "mal-ca2.crt"));
        X509Certificate leaf = (X509Certificate) cf.generateCertificate(TestResourceFinder.findTestResource("pkix", "mal-leaf.crt"));

        List certchain = new ArrayList();
        certchain.add(root);
        certchain.add(ca1);
        certchain.add(ca2);
        certchain.add(leaf);

        CertPath cp = cf.generateCertPath(certchain);

        Set trust = new HashSet();
        trust.add(new TrustAnchor(root, null));
        PKIXParameters param = new PKIXParameters(trust);

        PKIXCertPathReviewer certPathReviewer = new PKIXCertPathReviewer();
        certPathReviewer.init(cp, param);

        assertFalse(certPathReviewer.isValidCertPath()); // hit
    }

    public void testPKIXCertPathBuilder()
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        X509Certificate rootCert = (X509Certificate) cf.generateCertificate(TestResourceFinder.findTestResource("pkix", "mal-root.crt"));
        X509Certificate endCert = (X509Certificate) cf.generateCertificate(TestResourceFinder.findTestResource("pkix", "mal-ca1.crt"));

        // create CertStore to support path building
        List list = new ArrayList();
        list.add(endCert);

        CollectionCertStoreParameters params = new CollectionCertStoreParameters(list);
        CertStore                     store = CertStore.getInstance("Collection", params, "BC");

        // build the path
        CertPathBuilder  builder = CertPathBuilder.getInstance("PKIX", "BC");
        X509CertSelector pathConstraints = new X509CertSelector();

        pathConstraints.setCertificate(endCert);

        PKIXBuilderParameters buildParams = new PKIXBuilderParameters(Collections.singleton(new TrustAnchor(rootCert, null)), pathConstraints);

        buildParams.addCertStore(store);
        buildParams.setDate(new Date(1744869361113L)); // 17th April 2025
        buildParams.setRevocationEnabled(false);
        
        PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult)builder.build(buildParams);
        CertPath                  path = result.getCertPath();

        if (path.getCertificates().size() != 1)
        {
            fail("wrong number of certs in testPKIXCertPathBuilder path");
        }
    }

    public void testPKIXCertPathValidator()
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        X509Certificate rootCert = (X509Certificate) cf.generateCertificate(TestResourceFinder.findTestResource("pkix", "mal-root.crt"));
        X509Certificate endCert = (X509Certificate) cf.generateCertificate(TestResourceFinder.findTestResource("pkix", "mal-ca1.crt"));
        
        List list = new ArrayList();
        list.add(endCert);

        CertPath certPath = cf.generateCertPath(list);

        Set trust = new HashSet();
        trust.add(new TrustAnchor(rootCert, null));

        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", "BC");
        PKIXParameters param = new PKIXParameters(trust);
        param.setRevocationEnabled(false);
        param.setDate(new Date(1744869361113L)); // 17th April 2025

        cpv.validate(certPath, param);
    }

    /**
     * github #2320: a non-CA certificate carrying the name constraints
     * extension violates RFC 5280 section 4.2.1.10 ("MUST be used only in a
     * CA certificate") on the issuing CA's side. Path validation still
     * accepts the chain (matching the JDK and OpenSSL - the extension is
     * simply not processed in that position), but both PKIXCertPathReviewer
     * copies must surface the defect as a notification against the
     * offending certificate.
     */
    public void testNameConstraintsOnNonCACertNotification()
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        X509Certificate rootCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(NC_NON_CA_ROOT));
        X509Certificate endCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(NC_NON_CA_EE));

        CertPath certPath = cf.generateCertPath(Collections.singletonList(endCert));

        Set trust = new HashSet();
        trust.add(new TrustAnchor(rootCert, null));
        PKIXParameters param = new PKIXParameters(trust);
        param.setRevocationEnabled(false);

        // the path itself validates - the notification is diagnostic only
        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", "BC");
        cpv.validate(certPath, param);

        PKIXCertPathReviewer reviewer = new PKIXCertPathReviewer();
        reviewer.init(certPath, param);
        assertTrue("path should still review as valid", reviewer.isValidCertPath());
        assertTrue("pkix reviewer missing ncNonCACert notification",
            hasNotification(reviewer.getNotifications(0), "CertPathReviewer.ncNonCACert"));

        // the legacy org.bouncycastle.x509 copy must mirror the behaviour
        org.bouncycastle.x509.PKIXCertPathReviewer legacy = new org.bouncycastle.x509.PKIXCertPathReviewer();
        legacy.init(certPath, param);
        assertTrue("path should still review as valid (legacy)", legacy.isValidCertPath());
        assertTrue("legacy reviewer missing ncNonCACert notification",
            hasNotification(legacy.getNotifications(0), "CertPathReviewer.ncNonCACert"));

        // control: a CA certificate carrying name constraints must not be flagged
        assertFalse("CA cert wrongly flagged",
            hasNotification(reviewer.getNotifications(-1), "CertPathReviewer.ncNonCACert"));
    }

    private static boolean hasNotification(List notifications, String id)
    {
        for (int i = 0; i != notifications.size(); i++)
        {
            // the two reviewer copies use different ErrorBundle forks
            Object n = notifications.get(i);
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
