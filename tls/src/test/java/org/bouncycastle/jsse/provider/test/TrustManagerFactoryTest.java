package org.bouncycastle.jsse.provider.test;

import java.io.ByteArrayInputStream;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.util.encoders.Base64;

import junit.framework.TestCase;

public class TrustManagerFactoryTest
    extends TestCase
{
    public static byte[] rootCertBin = Base64.decode(
        "MIIBqzCCARQCAQEwDQYJKoZIhvcNAQEFBQAwHjEcMBoGA1UEAxMTVGVzdCBDQSBDZXJ0aWZpY2F0ZTAeFw0wODA5MDQwNDQ1MDhaFw0wODA5MTEwNDQ1MDhaMB4xHDAaBgNVBAMTE1Rlc3QgQ0EgQ2VydGlmaWNhdGUwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMRLUjhPe4YUdLo6EcjKcWUOG7CydFTH53Pr1lWjOkbmszYDpkhCTT9LOsI+disk18nkBxSl8DAHTqV+VxtuTPt64iyi10YxyDeep+DwZG/f8cVQv97U3hA9cLurZ2CofkMLGr6JpSGCMZ9FcstcTdHB4lbErIJ54YqfF4pNOs4/AgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAgyrTEFY7ALpeY59jL6xFOLpuPqoBOWrUWv6O+zy5BCU0qiX71r3BpigtxRj+DYcfLIM9FNERDoHu3TthD3nwYWUBtFX8N0QUJIdJabxqAMhLjSC744koiFpCYse5Ye3ZvEdFwDzgAQsJTp5eFGgTZPkPzcdhkFJ2p9+OWs+cb24=");

    static byte[] interCertBin = Base64.decode(
        "MIICSzCCAbSgAwIBAgIBATANBgkqhkiG9w0BAQUFADAeMRwwGgYDVQQDExNUZXN0IENBIENlcnRpZmljYXRlMB4XDTA4MDkwNDA0NDUwOFoXDTA4MDkxMTA0NDUwOFowKDEmMCQGA1UEAxMdVGVzdCBJbnRlcm1lZGlhdGUgQ2VydGlmaWNhdGUwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAISS9OOZ2wxzdWny9aVvk4Joq+dwSJ+oqvHUxX3PflZyuiLiCBUOUE4q59dGKdtNX5fIfwyK3cpV0e73Y/0fwfM3m9rOWFrCKOhfeswNTes0w/2PqPVVDDsF/nj7NApuqXwioeQlgTL251RDF4sVoxXqAU7lRkcqwZt3mwqS4KTJAgMBAAGjgY4wgYswRgYDVR0jBD8wPYAUhv8BOT27EB9JaCccJD4YASPP5XWhIqQgMB4xHDAaBgNVBAMTE1Rlc3QgQ0EgQ2VydGlmaWNhdGWCAQEwHQYDVR0OBBYEFL/IwAGOkHzaQyPZegy79CwM5oTFMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBBQUAA4GBAE4TRgUz4sUvZyVdZxqV+XyNRnqXAeLOOqFGYv2D96tQrS+zjd0elVlT6lFrtchZdOmmX7R6/H/tjMWMcTBICZyRYrvK8cCAmDOI+EIdq5p6lj2Oq6Pbw/wruojAqNrpaR6IkwNpWtdOSSupv4IJL+YU9q2YFTh4R1j3tOkPoFGr");

    static byte[] finalCertBin = Base64.decode(
        "MIICRjCCAa+gAwIBAgIBATANBgkqhkiG9w0BAQUFADAoMSYwJAYDVQQDEx1UZXN0IEludGVybWVkaWF0ZSBDZXJ0aWZpY2F0ZTAeFw0wODA5MDQwNDQ1MDhaFw0wODA5MTEwNDQ1MDhaMB8xHTAbBgNVBAMTFFRlc3QgRW5kIENlcnRpZmljYXRlMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQChpUeo0tPYywWKiLlbWKNJBcCpSaLSlaZ+4+yer1AxI5yJIVHP6SAlBghlbD5Qne5ImnN/15cz1xwYAiul6vGKJkVPlFEe2Mr+g/J/WJPQQPsjbZ1G+vxbAwXEDA4KaQrnpjRZFq+CdKHwOjuPLYS/MYQNgdIvDVEQcTbPQ8GaiQIDAQABo4GIMIGFMEYGA1UdIwQ/MD2AFL/IwAGOkHzaQyPZegy79CwM5oTFoSKkIDAeMRwwGgYDVQQDExNUZXN0IENBIENlcnRpZmljYXRlggEBMB0GA1UdDgQWBBSVkw+VpqBf3zsLc/9GdkK9TzHPwDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIFoDANBgkqhkiG9w0BAQUFAAOBgQBLv/0bVDjzTs/y1vN3FUiZNknEbzupIZduTuXJjqv/vBX+LDPjUfu/+iOCXOSKoRn6nlOWhwB1z6taG2usQkFG8InMkRcPREi2uVgFdhJ/1C3dAWhsdlubjdL926bftXvxnx/koDzyrePW5U96RlOQM2qLvbaky2Giz6hrc3Wl+w==");
    public static byte[] rootCrlBin = Base64.decode(
        "MIIBYjCBzAIBATANBgkqhkiG9w0BAQsFADAeMRwwGgYDVQQDExNUZXN0IENBIENlcnRpZmljYXRlFw0wODA5MDQwNDQ1MDhaFw0wODA5MDQwNzMxNDhaMCIwIAIBAhcNMDgwOTA0MDQ0NTA4WjAMMAoGA1UdFQQDCgEJoFYwVDBGBgNVHSMEPzA9gBSG/wE5PbsQH0loJxwkPhgBI8/ldaEipCAwHjEcMBoGA1UEAxMTVGVzdCBDQSBDZXJ0aWZpY2F0ZYIBATAKBgNVHRQEAwIBATANBgkqhkiG9w0BAQsFAAOBgQCAbaFCo0BNG4AktVf6jjBLeawP1u0ELYkOCEGvYZE0mBpQ+OvFg7subZ6r3lRIj030nUli28sPFtu5ZQMBNcpE4nS1ziF44RfT3Lp5UgHx9x17Krz781iEyV+7zU8YxYMY9wULD+DCuK294kGKIssVNbmTYXZatBNoXQN5CLIocA==");
    static byte[] interCrlBin = Base64.decode(
        "MIIBbDCB1gIBATANBgkqhkiG9w0BAQsFADAoMSYwJAYDVQQDEx1UZXN0IEludGVybWVkaWF0ZSBDZXJ0aWZpY2F0ZRcNMDgwOTA0MDQ0NTA4WhcNMDgwOTA0MDczMTQ4WjAiMCACAQIXDTA4MDkwNDA0NDUwOFowDDAKBgNVHRUEAwoBCaBWMFQwRgYDVR0jBD8wPYAUv8jAAY6QfNpDI9l6DLv0LAzmhMWhIqQgMB4xHDAaBgNVBAMTE1Rlc3QgQ0EgQ2VydGlmaWNhdGWCAQEwCgYDVR0UBAMCAQEwDQYJKoZIhvcNAQELBQADgYEAEVCr5TKs5yguGgLH+dBzmSPoeSIWJFLsgWwJEit/iUDJH3dgYmaczOcGxIDtbYYHLWIHM+P2YRyQz3MEkCXEgm/cx4y7leAmux5l+xQWgmxFPz+197vaphPeCZo+B7V1CWtm518gcq4mrs9ovfgNqgyFj7KGjcBpWdJE32KMt50=");

    private static final String CLIENT_AUTH_TYPE = "RSA";

    // NOTE: This depends on the value of JsseUtils.getAuthTypeServer(KeyExchangeAlgorithm.RSA)
//    private static final String SERVER_AUTH_TYPE = "RSA";
    private static final String SERVER_AUTH_TYPE = "KE:RSA";

    protected void setUp()
    {
        ProviderUtils.setupLowPriority(false);
    }

    public void testCertPathTrustManagerParameters() throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", ProviderUtils.PROVIDER_NAME_BC);

        // initialise CertStore
        X509Certificate rootCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(rootCertBin));
        X509Certificate interCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(interCertBin));
        X509Certificate finalCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(finalCertBin));
        X509CRL rootCrl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(rootCrlBin));
        X509CRL interCrl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(interCrlBin));
        List<Object> list = new ArrayList<Object>();
        list.add(rootCert);
        list.add(interCert);
        list.add(finalCert);
        list.add(rootCrl);
        list.add(interCrl);
        CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(list);
        CertStore store = CertStore.getInstance("Collection", ccsp, ProviderUtils.PROVIDER_NAME_BC);
        Date validDate = new Date(rootCrl.getThisUpdate().getTime() + 60 * 60 * 1000);

        //Searching for rootCert by subjectDN without CRL
        Set<TrustAnchor> trust = new HashSet<TrustAnchor>();
        trust.add(new TrustAnchor(rootCert, null));

        X509CertSelector targetConstraints = new X509CertSelector();
        targetConstraints.setSubject(finalCert.getSubjectX500Principal().getEncoded());
        PKIXBuilderParameters params = new PKIXBuilderParameters(trust, targetConstraints);
        params.addCertStore(store);
        params.setDate(validDate);

        if (Security.getProvider("IBMJSSE2") != null)
        {
            params.setRevocationEnabled(false);   // IBM cert path does not recognise setDate() fully.
        }
        else
        {
            params.setRevocationEnabled(true);
        }

        TrustManagerFactory fact = TrustManagerFactory.getInstance("PKIX", ProviderUtils.PROVIDER_NAME_BCJSSE);

        fact.init(new CertPathTrustManagerParameters(params));

        X509TrustManager trustManager = (X509TrustManager)fact.getTrustManagers()[0];

        assertEquals(rootCert, trustManager.getAcceptedIssuers()[0]);

        X509Certificate[] certs = new X509Certificate[]{ finalCert, interCert };

        trustManager.checkServerTrusted(certs, SERVER_AUTH_TYPE);
        trustManager.checkClientTrusted(certs, CLIENT_AUTH_TYPE);
    }

    public void testCertPathTrustManagerParametersFailure() throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", ProviderUtils.PROVIDER_NAME_BC);

        // initialise CertStore
        X509Certificate rootCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(rootCertBin));
        X509Certificate finalCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(finalCertBin));

        List<Object> list = new ArrayList<Object>();
        list.add(rootCert);
        list.add(finalCert);

        CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(list);
        CertStore store = CertStore.getInstance("Collection", ccsp, ProviderUtils.PROVIDER_NAME_BC);
        Date validDate = new Date(rootCert.getNotBefore().getTime() + 60 * 60 * 1000);

        //Searching for rootCert by subjectDN without CRL
        Set<TrustAnchor> trust = new HashSet<TrustAnchor>();
        trust.add(new TrustAnchor(rootCert, null));

        X509CertSelector targetConstraints = new X509CertSelector();
        targetConstraints.setSubject(finalCert.getSubjectX500Principal().getEncoded());
        PKIXBuilderParameters params = new PKIXBuilderParameters(trust, targetConstraints);
        params.addCertStore(store);
        params.setDate(validDate);
        params.setRevocationEnabled(false);

        TrustManagerFactory fact = TrustManagerFactory.getInstance("PKIX", ProviderUtils.PROVIDER_NAME_BCJSSE);

        fact.init(new CertPathTrustManagerParameters(params));

        X509TrustManager trustManager = (X509TrustManager)fact.getTrustManagers()[0];

        assertEquals(rootCert, trustManager.getAcceptedIssuers()[0]);

        X509Certificate[] certs = new X509Certificate[]{ finalCert };

        try
        {
            trustManager.checkServerTrusted(certs, SERVER_AUTH_TYPE);
            fail("no exception");
        }
        catch (CertificateException e)
        {
            // expected
        }

        try
        {
            trustManager.checkClientTrusted(certs, CLIENT_AUTH_TYPE);
            fail("no exception");
        }
        catch (CertificateException e)
        {
            // expected
        }
    }
}
