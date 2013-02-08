package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.Vector;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;

public class CertPathTest
    extends SimpleTest
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

    /*
     * certpath with a circular reference
     */
    static byte[] certA = Base64.decode(
        "MIIC6jCCAlOgAwIBAgIBBTANBgkqhkiG9w0BAQUFADCBjTEPMA0GA1UEAxMGSW50"
      + "ZXIzMQswCQYDVQQGEwJDSDEPMA0GA1UEBxMGWnVyaWNoMQswCQYDVQQIEwJaSDEX"
      + "MBUGA1UEChMOUHJpdmFzcGhlcmUgQUcxEDAOBgNVBAsTB1Rlc3RpbmcxJDAiBgkq"
      + "hkiG9w0BCQEWFWFybWluQHByaXZhc3BoZXJlLmNvbTAeFw0wNzA0MDIwODQ2NTda"
      + "Fw0xNzAzMzAwODQ0MDBaMIGlMScwJQYDVQQDHh4AQQByAG0AaQBuACAASADkAGIA"
      + "ZQByAGwAaQBuAGcxCzAJBgNVBAYTAkNIMQ8wDQYDVQQHEwZadXJpY2gxCzAJBgNV"
      + "BAgTAlpIMRcwFQYDVQQKEw5Qcml2YXNwaGVyZSBBRzEQMA4GA1UECxMHVGVzdGlu"
      + "ZzEkMCIGCSqGSIb3DQEJARYVYXJtaW5AcHJpdmFzcGhlcmUuY29tMIGfMA0GCSqG"
      + "SIb3DQEBAQUAA4GNADCBiQKBgQCfHfyVs5dbxG35H/Thd29qR4NZU88taCu/OWA1"
      + "GdACI02lXWYpmLWiDgnU0ULP+GG8OnVp1IES9fz2zcrXKQ19xZzsen/To3h5sNte"
      + "cJpS00XMM24q/jDwy5NvkBP9YIfFKQ1E/0hFHXcqwlw+b/y/v6YGsZCU2h6QDzc4"
      + "5m0+BwIDAQABo0AwPjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIE8DAeBglg"
      + "hkgBhvhCAQ0EERYPeGNhIGNlcnRpZmljYXRlMA0GCSqGSIb3DQEBBQUAA4GBAJEu"
      + "KiSfIwsY7SfobMLrv2v/BtLhGLi4RnmjiwzBhuv5rn4rRfBpq1ppmqQMJ2pmA67v"
      + "UWCY+mNwuyjHyivpCCyJGsZ9d5H09g2vqxzkDBMz7X9VNMZYFH8j/R3/Cfvqks31"
      + "z0OFslJkeKLa1I0P/dfVHsRKNkLRT3Ws5LKksErQ");

    static byte[] certB = Base64.decode(
        "MIICtTCCAh6gAwIBAgIBBDANBgkqhkiG9w0BAQQFADCBjTEPMA0GA1UEAxMGSW50"
      + "ZXIyMQswCQYDVQQGEwJDSDEPMA0GA1UEBxMGWnVyaWNoMQswCQYDVQQIEwJaSDEX"
      + "MBUGA1UEChMOUHJpdmFzcGhlcmUgQUcxEDAOBgNVBAsTB1Rlc3RpbmcxJDAiBgkq"
      + "hkiG9w0BCQEWFWFybWluQHByaXZhc3BoZXJlLmNvbTAeFw0wNzA0MDIwODQ2Mzha"
      + "Fw0xNzAzMzAwODQ0MDBaMIGNMQ8wDQYDVQQDEwZJbnRlcjMxCzAJBgNVBAYTAkNI"
      + "MQ8wDQYDVQQHEwZadXJpY2gxCzAJBgNVBAgTAlpIMRcwFQYDVQQKEw5Qcml2YXNw"
      + "aGVyZSBBRzEQMA4GA1UECxMHVGVzdGluZzEkMCIGCSqGSIb3DQEJARYVYXJtaW5A"
      + "cHJpdmFzcGhlcmUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCxCXIB"
      + "QRnmVvl2h7Q+0SsRxDLnyM1dJG9jMa+UCCmHy0k/ZHs5VirSbjEJSjkQ9BGeh9SC"
      + "7JwbMpXO7UE+gcVc2RnWUY+MA+fWIeTV4KtkYA8WPu8wVGCXbN8wwh/StOocszxb"
      + "g+iLvGeh8CYSRqg6QN3S/02etH3o8H4e7Z0PZwIDAQABoyMwITAPBgNVHRMBAf8E"
      + "BTADAQH/MA4GA1UdDwEB/wQEAwIB9jANBgkqhkiG9w0BAQQFAAOBgQCtWdirSsmt"
      + "+CBBCNn6ZnbU3QqQfiiQIomjenNEHESJgaS/+PvPE5i3xWFXsunTHLW321/Km16I"
      + "7+ZvT8Su1cqHg79NAT8QB0yke1saKSy2C0Pic4HwrNqVBWFNSxMU0hQzpx/ZXDbZ"
      + "DqIXAp5EfyRYBy2ul+jm6Rot6aFgzuopKg==");

    static byte[] certC = Base64.decode(
        "MIICtTCCAh6gAwIBAgIBAjANBgkqhkiG9w0BAQQFADCBjTEPMA0GA1UEAxMGSW50"
      + "ZXIxMQswCQYDVQQGEwJDSDEPMA0GA1UEBxMGWnVyaWNoMQswCQYDVQQIEwJaSDEX"
      + "MBUGA1UEChMOUHJpdmFzcGhlcmUgQUcxEDAOBgNVBAsTB1Rlc3RpbmcxJDAiBgkq"
      + "hkiG9w0BCQEWFWFybWluQHByaXZhc3BoZXJlLmNvbTAeFw0wNzA0MDIwODQ0Mzla"
      + "Fw0xNzAzMzAwODQ0MDBaMIGNMQ8wDQYDVQQDEwZJbnRlcjIxCzAJBgNVBAYTAkNI"
      + "MQ8wDQYDVQQHEwZadXJpY2gxCzAJBgNVBAgTAlpIMRcwFQYDVQQKEw5Qcml2YXNw"
      + "aGVyZSBBRzEQMA4GA1UECxMHVGVzdGluZzEkMCIGCSqGSIb3DQEJARYVYXJtaW5A"
      + "cHJpdmFzcGhlcmUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD0rLr6"
      + "f2/ONeJzTb0q9M/NNX+MnAFMSqiQGVBkT76u5nOH4KLkpHXkzI82JI7GuQMzoT3a"
      + "+RP1hO6FneO92ms2soC6xiOFb4EC69Dfhh87Nww5O35JxVF0bzmbmIAWd6P/7zGh"
      + "nd2S4tKkaZcubps+C0j9Fgi0hipVicAOUVVoDQIDAQABoyMwITAPBgNVHRMBAf8E"
      + "BTADAQH/MA4GA1UdDwEB/wQEAwIB9jANBgkqhkiG9w0BAQQFAAOBgQCLPvc1IMA4"
      + "YP+PmnEldyUoRWRnvPWjBGeu0WheBP7fdcnGBf93Nmc5j68ZN+eTZ5VMuZ99YdvH"
      + "CXGNX6oodONLU//LlFKdLl5xjLAS5X9p1RbOEGytnalqeiEpjk4+C/7rIBG1kllO"
      + "dItmI6LlEMV09Hkpg6ZRAUmRkb8KrM4X7A==");

    static byte[] certD = Base64.decode(
        "MIICtTCCAh6gAwIBAgIBBjANBgkqhkiG9w0BAQQFADCBjTEPMA0GA1UEAxMGSW50"
      + "ZXIzMQswCQYDVQQGEwJDSDEPMA0GA1UEBxMGWnVyaWNoMQswCQYDVQQIEwJaSDEX"
      + "MBUGA1UEChMOUHJpdmFzcGhlcmUgQUcxEDAOBgNVBAsTB1Rlc3RpbmcxJDAiBgkq"
      + "hkiG9w0BCQEWFWFybWluQHByaXZhc3BoZXJlLmNvbTAeFw0wNzA0MDIwODQ5NTNa"
      + "Fw0xNzAzMzAwODQ0MDBaMIGNMQ8wDQYDVQQDEwZJbnRlcjExCzAJBgNVBAYTAkNI"
      + "MQ8wDQYDVQQHEwZadXJpY2gxCzAJBgNVBAgTAlpIMRcwFQYDVQQKEw5Qcml2YXNw"
      + "aGVyZSBBRzEQMA4GA1UECxMHVGVzdGluZzEkMCIGCSqGSIb3DQEJARYVYXJtaW5A"
      + "cHJpdmFzcGhlcmUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCae3TP"
      + "jIVKeASqvNabaiUHAMGUgFxB7L0yUsIj39azLcLtUj4S7XkDf7SMGtYV0JY1XNaQ"
      + "sHJAsnJivDZc50oiYvqDYfgFZx5+AsN5l5X5rjRzs/OX+Jo+k1OgsIyu6+mf9Kfb"
      + "5IdWOVB2EcOg4f9tPjLM8CIj9Pp7RbKLyqUUgwIDAQABoyMwITAPBgNVHRMBAf8E"
      + "BTADAQH/MA4GA1UdDwEB/wQEAwIB9jANBgkqhkiG9w0BAQQFAAOBgQCgr9kUdWUT"
      + "Lt9UcztSzR3pnHRsyvS0E/z850OKQKS5/VxLEalpFvhj+3EcZ7Y6mFxaaS2B7vXg"
      + "2YWyqV1PRb6iF7/u9EXkpSTKGrJahwANirCa3V/HTUuPdCE2GITlnWI8h3eVA+xQ"
      + "D4LF0PXHOkXbwmhXRSb10lW1bSGkUxE9jg==");

    private void testExceptions()
        throws Exception
    {
        byte[] enc = { (byte)0, (byte)2, (byte)3, (byte)4, (byte)5 };
        MyCertPath mc = new MyCertPath(enc);
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        ByteArrayInputStream is;
        byte[] arr;

        ObjectOutputStream oOut = new ObjectOutputStream(os);
        oOut.writeObject(mc);
        oOut.flush();
        oOut.close();

        try
        {
            CertificateFactory cFac = CertificateFactory.getInstance("X.509",
                    "BC");
            arr = os.toByteArray();
            is = new ByteArrayInputStream(arr);
            cFac.generateCertPath(is);
        }
        catch (CertificateException e)
        {
            // ignore okay
        }

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List certCol = new ArrayList();

        certCol.add(cf.generateCertificate(new ByteArrayInputStream(certA)));
        certCol.add(cf.generateCertificate(new ByteArrayInputStream(certB)));
        certCol.add(cf.generateCertificate(new ByteArrayInputStream(certC)));
        certCol.add(cf.generateCertificate(new ByteArrayInputStream(certD)));

        CertPathBuilder pathBuilder = CertPathBuilder.getInstance("PKIX", "BC");
        X509CertSelector select = new X509CertSelector();
        select.setSubject(((X509Certificate)certCol.get(0)).getSubjectX500Principal().getEncoded());

        Set trustanchors = new HashSet();
        trustanchors.add(new TrustAnchor((X509Certificate)cf.generateCertificate(new ByteArrayInputStream(rootCertBin)), null));

        CertStore certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certCol));

        PKIXBuilderParameters params = new PKIXBuilderParameters(trustanchors, select);
        params.addCertStore(certStore);

        try
        {
            CertPathBuilderResult result = pathBuilder.build(params);
            CertPath path = result.getCertPath();
            fail("found cert path in circular set");
        }
        catch (CertPathBuilderException e) 
        {
            // expected
        }
    }
    
    public void performTest()
        throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        X509Certificate rootCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(rootCertBin));
        X509Certificate interCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(interCertBin));
        X509Certificate finalCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(finalCertBin));

            //Testing CertPath generation from List
        List list = new ArrayList();
        list.add(interCert);
        CertPath certPath1 = cf.generateCertPath(list);

            //Testing CertPath encoding as PkiPath
        byte[] encoded = certPath1.getEncoded("PkiPath");

            //Testing CertPath generation from InputStream
        ByteArrayInputStream inStream = new ByteArrayInputStream(encoded);
        CertPath certPath2 = cf.generateCertPath(inStream, "PkiPath");

            //Comparing both CertPathes
        if (!certPath2.equals(certPath1))
        {
            fail("CertPath differ after encoding and decoding.");
        }

        encoded = certPath1.getEncoded("PKCS7");

            //Testing CertPath generation from InputStream
        inStream = new ByteArrayInputStream(encoded);
        certPath2 = cf.generateCertPath(inStream, "PKCS7");

            //Comparing both CertPathes
        if (!certPath2.equals(certPath1))
        {
            fail("CertPath differ after encoding and decoding.");
        }

        encoded = certPath1.getEncoded("PEM");

            //Testing CertPath generation from InputStream
        inStream = new ByteArrayInputStream(encoded);
        certPath2 = cf.generateCertPath(inStream, "PEM");

            //Comparing both CertPathes
        if (!certPath2.equals(certPath1))
        {
            fail("CertPath differ after encoding and decoding.");
        }

        //
        // empty list test
        //
        list = new ArrayList();

        CertPath certPath = CertificateFactory.getInstance("X.509","BC").generateCertPath(list);
        if (certPath.getCertificates().size() != 0)
        {
            fail("list wrong size.");
        }

        //
        // exception tests
        //
        testExceptions();
    }

    public String getName()
    {
        return "CertPath";
    }

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new CertPathTest());
    }

    private static class MyCertificate extends Certificate
    {
        private final byte[] encoding;

        public MyCertificate(String type, byte[] encoding)
        {
            super(type);
            // don't copy to allow null parameter in test
            this.encoding = encoding;
        }

        public byte[] getEncoded() throws CertificateEncodingException
        {
            // do copy to force NPE in test
            return (byte[])encoding.clone();
        }

        public void verify(PublicKey key) throws CertificateException,
                NoSuchAlgorithmException, InvalidKeyException,
                NoSuchProviderException, SignatureException
        {
        }

        public void verify(PublicKey key, String sigProvider)
                throws CertificateException, NoSuchAlgorithmException,
                InvalidKeyException, NoSuchProviderException,
                SignatureException
        {
        }

        public String toString()
        {
            return "[My test Certificate, type: " + getType() + "]";
        }

        public PublicKey getPublicKey()
        {
            return new PublicKey()
            {
                public String getAlgorithm()
                {
                    return "TEST";
                }

                public byte[] getEncoded()
                {
                    return new byte[] { (byte)1, (byte)2, (byte)3 };
                }

                public String getFormat()
                {
                    return "TEST_FORMAT";
                }
            };
        }
    }

    private static class MyCertPath extends CertPath
    {
        private final Vector certificates;

        private final Vector encodingNames;

        private final byte[] encoding;

        public MyCertPath(byte[] encoding)
        {
            super("MyEncoding");
            this.encoding = encoding;
            certificates = new Vector();
            certificates.add(new MyCertificate("MyEncoding", encoding));
            encodingNames = new Vector();
            encodingNames.add("MyEncoding");
        }

        public List getCertificates()
        {
            return Collections.unmodifiableList(certificates);
        }

        public byte[] getEncoded() throws CertificateEncodingException
        {
            return (byte[])encoding.clone();
        }

        public byte[] getEncoded(String encoding)
                throws CertificateEncodingException
        {
            if (getType().equals(encoding))
            {
                return (byte[])this.encoding.clone();
            }
            throw new CertificateEncodingException("Encoding not supported: "
                    + encoding);
        }

        public Iterator getEncodings()
        {
            return Collections.unmodifiableCollection(encodingNames).iterator();
        }
    }
}

