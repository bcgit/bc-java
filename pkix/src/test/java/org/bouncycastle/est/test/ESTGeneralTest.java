package org.bouncycastle.est.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.selector.X509CertificateHolderSelector;
import org.bouncycastle.cmc.SimplePKIResponse;
import org.bouncycastle.est.CSRAttributesResponse;
import org.bouncycastle.est.ESTResponse;
import org.bouncycastle.est.ESTService;
import org.bouncycastle.est.EnrollmentResponse;
import org.bouncycastle.est.HttpAuth;
import org.bouncycastle.est.LimitedSource;
import org.bouncycastle.est.Source;
import org.bouncycastle.est.jcajce.JcaHttpAuthBuilder;
import org.bouncycastle.est.jcajce.JcaJceUtils;
import org.bouncycastle.est.jcajce.JsseESTServiceBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.test.GeneralTest;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.junit.Assert;
import org.junit.Test;

public class ESTGeneralTest
    extends GeneralTest
{
    public static void main(String[] args)
        throws Exception
    {
        ESTGeneralTest test = new ESTGeneralTest();
        test.setUp();
        test.testParsingCsrattrs1();
        test.testParsingCacertsResponse();
        test.testESTResponseShouldParseHttp11();
    }

    public void testParsingCacertsResponse()
        throws Exception
    {
        //Tests for SimplePKIResponse
        testException("malformed data: ", "CMCException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new SimplePKIResponse(new byte[100]);
            }
        });

        SimplePKIResponse response = new SimplePKIResponse(ESTParsingTest.cacertsResponse);
        assertEquals(0, response.getCRLs().getMatches(null).size());
        assertNotNull(response.getEncoded());
        Store<X509CertificateHolder> certs = response.getCertificates();

        assertEquals(4, certs.getMatches(null).size());

        assertEquals(1, certs.getMatches(new X509CertificateHolderSelector(new X500Name("CN=estExampleCA OwO"), new BigInteger("11121883874307308188"))).size());
        assertEquals(1, certs.getMatches(new X509CertificateHolderSelector(new X500Name("CN=estExampleCA OwO"), new BigInteger("1"))).size());
        assertEquals(1, certs.getMatches(new X509CertificateHolderSelector(new X500Name("CN=estExampleCA NwN"), new BigInteger("2"))).size());
        assertEquals(1, certs.getMatches(new X509CertificateHolderSelector(new X500Name("CN=estExampleCA NwN"), new BigInteger("16838569520216125969"))).size());
    }

    public void testParsingCsrattrs1()
        throws Exception
    {
        testException("malformed data: ", "ESTException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new CSRAttributesResponse(new byte[100]);
            }
        });
        CSRAttributesResponse response = new CSRAttributesResponse(ESTParsingTest.csrattrs1);
        response = new CSRAttributesResponse(response.getEncoded());
        assertFalse(response.isEmpty());
        assertTrue(response.hasRequirement(PKCSObjectIdentifiers.pkcs_9_at_challengePassword));
        assertTrue(response.hasRequirement(X9ObjectIdentifiers.ecdsa_with_SHA384));
        assertFalse(response.isAttribute(X9ObjectIdentifiers.c2onb191v4));
        assertFalse(response.isAttribute(X9ObjectIdentifiers.ecdsa_with_SHA384));
        assertTrue(response.isAttribute(X9ObjectIdentifiers.id_ecPublicKey));
        assertTrue(response.isAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest));

        Collection<ASN1ObjectIdentifier> requirements = response.getRequirements();

        assertEquals(4, requirements.size());

        testException("malformed data: ", "PKCSIOException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new PKCS10CertificationRequest(ESTParsingTest.csrattrs1);
            }
        });
    }

    public void testESTResponseShouldParseHttp11()
        throws IOException
    {
        String data = "Test message body";
        Map<String, String> httpHeader = new HashMap<String, String>();
        httpHeader.put("Content-Length", String.valueOf(data.length()));
        httpHeader.put("X-BC-EST-Header", "Test");

        InputStream testHttp11ResponseData = ESTResponseTest.buildHttp11Response("200 OK", httpHeader, false, data);

        ESTResponse response = new ESTResponse(null, ESTResponseTest.getMockSource(testHttp11ResponseData));
        assertEquals(response.getAbsoluteReadLimit(), Long.MAX_VALUE);
        assertEquals(2, ((HashMap)response.getHeaders()).size());
        assertNull(response.getOriginalRequest());
        assertEquals(200, response.getStatusCode());
        assertEquals(Long.valueOf(data.length()), response.getContentLength());
        assertEquals("Test", response.getHeaderOrEmpty("X-BC-EST-Header"));
        assertEquals("OK", response.getStatusMessage());
        assertEquals("HTTP/1.1", response.getHttpVersion());
        assertNotNull(response.getSource());
        ESTResponseTest.assertESTResponseMessageEquals(data, response);
        response.close();

        testException("Content length longer than absolute read limit: ", "IOException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

                PrintWriter pw = new PrintWriter(responseData);
                pw.print("HTTP/1.1 200 OK\n" +
                    "Status: 200 OK\n" +
                    "Content-Type: application/pkcs7-mime\n" +
                    "Content-Transfer-Encoding: base64\n" +
                    "Content-Length: 10\n" +
                    "\n" +
                    "MIIBggYJKoZIhvcNAQcCoIIBczCCAW8CAQExADALBgkqhkiG9w0BBwGgggFXMIIB\n" +
                    "UzCB+qADAgECAgkA+syTlV9djhkwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMZXN0\n" +
                    "RXhhbXBsZUNBMB4XDTE3MDIxODAyNTQ1OVoXDTE4MDIxODAyNTQ1OVowFzEVMBMG\n" +
                    "A1UEAwwMZXN0RXhhbXBsZUNBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEobjd\n" +
                    "xMcCE5GfVRE4f86ik6yK0erBhAbN8er0u6vWTXlyk5IXJy7HsUmC7Wv1SDRno/Rp\n" +
                    "pyVekSu4T0/h7uBeaKMvMC0wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQU8rjiAzjo\n" +
                    "Nldka5gT1bcbQqcESPMwCgYIKoZIzj0EAwIDSAAwRQIhAOwsMtixDryuVUYNBdaf\n" +
                    "3tQV1SlvBmCP6y3cKMST45sRAiBEUNYOsYnuFmH93I+0NSJPYuuBY+Zfqrc2awCs\n" +
                    "spOU3zEA");

                pw.flush();
                ESTResponse response2 = new ESTResponse(null, new LimitedSource(){


                    public InputStream getInputStream()
                        throws IOException
                    {
                        return new ByteArrayInputStream(responseData.toByteArray());
                    }


                    public OutputStream getOutputStream()
                        throws IOException
                    {
                        return null;
                    }


                    public Object getSession()
                    {
                        return null;
                    }

                    @Override
                    public void close()
                        throws IOException
                    {

                    }

                    @Override
                    public Long getAbsoluteReadLimit()
                    {
                        return 0L;
                    }
                });
            }
        });

        testException("Got HTTP status 204 but Content-length > 0.", "IOException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

                PrintWriter pw = new PrintWriter(responseData);
                pw.print("HTTP/1.1 204 OK\n" +
                    "Status: 204 OK\n" +
                    "Content-Type: application/pkcs7-mime\n" +
                    "Content-Transfer-Encoding: base64\n" +
                    "Content-Length: 10\n" +
                    "\n" +
                    "MIIBggYJKoZIhvcNAQcCoIIBczCCAW8CAQExADALBgkqhkiG9w0BBwGgggFXMIIB\n" +
                    "UzCB+qADAgECAgkA+syTlV9djhkwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMZXN0\n" +
                    "RXhhbXBsZUNBMB4XDTE3MDIxODAyNTQ1OVoXDTE4MDIxODAyNTQ1OVowFzEVMBMG\n" +
                    "A1UEAwwMZXN0RXhhbXBsZUNBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEobjd\n" +
                    "xMcCE5GfVRE4f86ik6yK0erBhAbN8er0u6vWTXlyk5IXJy7HsUmC7Wv1SDRno/Rp\n" +
                    "pyVekSu4T0/h7uBeaKMvMC0wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQU8rjiAzjo\n" +
                    "Nldka5gT1bcbQqcESPMwCgYIKoZIzj0EAwIDSAAwRQIhAOwsMtixDryuVUYNBdaf\n" +
                    "3tQV1SlvBmCP6y3cKMST45sRAiBEUNYOsYnuFmH93I+0NSJPYuuBY+Zfqrc2awCs\n" +
                    "spOU3zEA");

                pw.flush();
                ESTResponse response2 = new ESTResponse(null, new LimitedSource(){


                    public InputStream getInputStream()
                        throws IOException
                    {
                        return new ByteArrayInputStream(responseData.toByteArray());
                    }


                    public OutputStream getOutputStream()
                        throws IOException
                    {
                        return null;
                    }


                    public Object getSession()
                    {
                        return null;
                    }

                    @Override
                    public void close()
                        throws IOException
                    {

                    }

                    @Override
                    public Long getAbsoluteReadLimit()
                    {
                        return 0L;
                    }
                });
            }
        });

        testException("Content length longer than absolute read limit: ", "IOException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

                PrintWriter pw = new PrintWriter(responseData);
                pw.print("HTTP/1.1 204 OK\n" +
                    "Status: 204 OK\n" +
                    "Content-Type: application/pkcs7-mime\n" +
                    "Content-Transfer-Encoding: base64\n" +
                    "\n" +
                    "MIIBggYJKoZIhvcNAQcCoIIBczCCAW8CAQExADALBgkqhkiG9w0BBwGgggFXMIIB\n" +
                    "UzCB+qADAgECAgkA+syTlV9djhkwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMZXN0\n" +
                    "RXhhbXBsZUNBMB4XDTE3MDIxODAyNTQ1OVoXDTE4MDIxODAyNTQ1OVowFzEVMBMG\n" +
                    "A1UEAwwMZXN0RXhhbXBsZUNBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEobjd\n" +
                    "xMcCE5GfVRE4f86ik6yK0erBhAbN8er0u6vWTXlyk5IXJy7HsUmC7Wv1SDRno/Rp\n" +
                    "pyVekSu4T0/h7uBeaKMvMC0wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQU8rjiAzjo\n" +
                    "Nldka5gT1bcbQqcESPMwCgYIKoZIzj0EAwIDSAAwRQIhAOwsMtixDryuVUYNBdaf\n" +
                    "3tQV1SlvBmCP6y3cKMST45sRAiBEUNYOsYnuFmH93I+0NSJPYuuBY+Zfqrc2awCs\n" +
                    "spOU3zEA");

                pw.flush();
                ESTResponse response2 = new ESTResponse(null, new LimitedSource(){


                    public InputStream getInputStream()
                        throws IOException
                    {
                        return new ByteArrayInputStream(responseData.toByteArray());
                    }


                    public OutputStream getOutputStream()
                        throws IOException
                    {
                        return null;
                    }


                    public Object getSession()
                    {
                        return null;
                    }

                    @Override
                    public void close()
                        throws IOException
                    {

                    }

                    @Override
                    public Long getAbsoluteReadLimit()
                    {
                        return 0L;
                    }
                });
            }
        });
    }


}
