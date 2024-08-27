package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Random;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.OcspResponseManager;
import org.bouncycastle.jce.provider.RecoverableCertPathValidatorException;
import org.bouncycastle.test.PrintTestResult;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Assert;

public class OcspResponseManagerTest extends TestCase
{
    private static final JcaJceHelper helper = new BCJcaJceHelper();
    // 2 certs with AIA extension with OCSP URI: http://localhost:30080/
    private static final byte[] cert = Base64.decode("MIIEsDCCAxigAwIBAgIUDnYM/pwIoSCjrZPrDzXcynrvwdkwDQYJKoZIhvcNAQELBQAwFTETMBEGA1UEAwwKSVNTVUlOR0NBNDAeFw0yNDA2MDcxNTE4NDlaFw0yNTA2MDcxNTE0NTVaMDwxETAPBgNVBAMMCDAxMDAwMDA0MQwwCgYDVQQLDANLTUMxDDAKBgNVBAoMA1RIQTELMAkGA1UEBhMCR0IwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCucOM9+XjY3eV2kRy1IR/j8GVld3hENS4CnoHnqWcNKviBlaKGRPRUbd/w+8J7Uaw5oI7W7KoBeFaIJaXQ4V2Gn6JGEhGu6RaOHriIMObRpx31AinT1kYjIgWjHmrOB6E4LzaxkFoM+sbS2SKyZaWPgIKySzbfO+YEqmBqTVIweWpNxv/uqdFtv+HIMZyWuAATAEwdPlgbzLs6RqN7BaIutQ4PRI9V43x5B4xWNIXn+8nMd4WyEkCOCKRTvmajHlRcfvq+iOVEXtHkKS6MysLknEvc7TiPFJRR0zKgA3InPGezPS6fCQmMS4ZMphBoO9iYKfDsvJoZKKEsWkyb6sw6IP5h+/rClfEe/kTkai0CuPPQK/Pse4F/Iau106VlTfZZcr+8g3Qs9mIJIj6PMTv81nwSzrz8O/fHPPqOLAr7apUtZnT5s6KWlD2bvD4BYvfIgTl8UTBi6w3NSeglV8+nMNfeY9vCGICxpQHWLJpeMPIJW6yokM+rDd3FUN0ivRUCAwEAAaOB0DCBzTAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFJLTr+Z11eQ5xaTdZRKhiGChKZYRME4GCCsGAQUFBwEBBEIwQDA+BggrBgEFBQcwAYYyaHR0cDovL2xvY2FsaG9zdDozMDA4MC9lamJjYS9wdWJsaWN3ZWIvc3RhdHVzL29jc3AwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMB0GA1UdDgQWBBRVYOKvDRtKQkT3viG6fCoo6EHDWDAOBgNVHQ8BAf8EBAMCBaAwDQYJKoZIhvcNAQELBQADggGBAAIS9ydwWiWLo+sZ9W8j9cQvDmE1NBGGNNmB8Z+1LT3aqnjubYevs1+Nds9zHJkiiFay+61ACRtpzO13JeXabd8VmINox1qCVNl29f8a6L3JTA1Zomjj4mGHZXzh51diHawXsE+9AlAN2BwEegaqnJpfR8X70wof08cEcwdaS5ekDWld+nSI23KAKf/0bUW9rcj40WoZUs7As6dL/PIGHRebmuGsRiPzoOnDJVicWVJBx1aKmvBezu0TQF1mjwTlJeODuI3u3dInfxdWpBOJ5xNOq/jBHAEwWi5j6nR0ZNTqfXL2ITIUylL/PWMzopjxQCGELRUrmu2XVuuCtARmtHLACy24DJRaVxKFtCBboPFm0oV0N8+MemfhUV0tvZUlpUciQSp/EkfCe3k8Up2ALWnATOuF/jA3uRxOHiOxpUWMjrmk2sQj3xxD1xqWGqF6/J9aM1GpAQ/Pe9xodQ+S5oAkccKy8EfKgrN5//njBtVM/LKwHgeELsnRQoGFc/zemw==");
    private static final byte[] issuer = Base64.decode("MIIEkDCCAvigAwIBAgIUX4IMXA0kGXbVq2V/IxJrZPFV+towDQYJKoZIhvcNAQEMBQAwODEPMA0GA1UEAwwGUk9PVENBMQswCQYDVQQLDAJDQTELMAkGA1UECgwCTlIxCzAJBgNVBAYTAkdCMB4XDTI0MDYwNzE1MTg0OVoXDTI1MDYwNzE1MTg0OFowFTETMBEGA1UEAwwKSVNTVUlOR0NBNDCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAJf2IrOdAQw6GcZ1m2+3y/OcAXm9pCjdfN0ydC5dqsBC62oHuMOSk/q8ZiOGrPEc/ONcTV0q0sKDNWyDZxmbQxeL2Y22eIcrS/jRDtNaIoidb0JLzL0tpdh7WNZxhLlpH2XuT60OER1Oo3ZPSi1f5O3LFbC2ZIABvRt9Ldp4yKwNQ78Zkvf855aAYjZ2RVAq0+6kqMDTmLn5HJey8ayZroKuF88Ns/lZWk+J7mjUo3XZZFVbM6k1LO/A4nK3E/Dsbv7EOxy8cke562qKpl6XxrEiZfFaxFEuwGzgi7skpayku8TEpMDW0fx5KChcQlEvuHAwyjkC4miRkGjmqVhfZUIjUZzl/I43S+5eooUqqxeTnOR8J9lfW3a8E4FZNGSn3Tx9x9N2zZHe8mziRv73C00pNHFGA1EjLjigiHHlgjgoyzKj3pEN/NMl65TS0Qxm0dPvpAn0Q7eZUYbPtRRVBESQGEQ2JTE4XmdzTF+c42edWMROkUi4Juxdsm1sJvaDXwIDAQABo4G0MIGxMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUNNt4P8rFkBaOpmL+oUia6c+KHNowTgYIKwYBBQUHAQEEQjBAMD4GCCsGAQUFBzABhjJodHRwOi8vbG9jYWxob3N0OjMwMDgwL2VqYmNhL3B1YmxpY3dlYi9zdGF0dXMvb2NzcDAdBgNVHQ4EFgQUktOv5nXV5DnFpN1lEqGIYKEplhEwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBDAUAA4IBgQBD9H6KTN4nM+KbOwQrxsaH5F8WnlrZSJ9g5csbayVGReZJtuRzigF8IOel2/E3JUgfKUxvGDCd3ZPxHkjNLeWl6dTr4jDFsg1QL1xVdb5Bxb7FR2Og9DtRf3+InoTIe10cNngK7+V83DSmNxy7i5Ygj4KhiRm3jegbVx2wkjmtHQRhczaVNH1/qiGWILT0t46M0TYcZzIcO5/6JUwZlDWLoc4KzvSKvTaEk4mASeYl4HHqoi96FBlGV3KacqlznCsZO/k0lZ6RflJwvX3OTAwXD11iIht+CQuxnGh2ZRQ9KP62eeu4EBxf3fqOQiwU/pHx1TdLyu/n/uh0ZTFazazjhE/PuBaCy+qrdC22weyunpp7bNbRF1B65Rs9EsuertMDA3kTTyYicpK7/ihbuFYmzfZFuMoNOLtgZGTfHqPjcaEkHmlDOP0m1fiwrfWe8LjXGgjE53Yy0yFPO23BCkK7eWh74aojVICRXL+j53nn6fhJ8+tTVJmAWACPi7ct0J4=");
    // OCSP response to be returned by our simple server
    private static final byte[] response = Base64.decode("MIIFnAoBAKCCBZUwggWRBgkrBgEFBQcwAQEEggWCMIIFfjCCARehgZ8wgZwxCzAJBgNVBAYTAklOMRcwFQYDVQQIEw5BbmRocmEgcHJhZGVzaDESMBAGA1UEBxMJSHlkZXJhYmFkMQwwCgYDVQQKEwNUQ1MxDDAKBgNVBAsTA0FUQzEeMBwGA1UEAxMVVENTLUNBIE9DU1AgUmVzcG9uZGVyMSQwIgYJKoZIhvcNAQkBFhVvY3NwQHRjcy1jYS50Y3MuY28uaW4YDzIwMDMwNDAyMTIzNDU4WjBiMGAwOjAJBgUrDgMCGgUABBRs07IuoCWNmcEl1oHwIak1BPnX8QQUtGyl/iL9WJ1VxjxFj0hAwJ/s1AcCAQKhERgPMjAwMjA4MjkwNzA5MjZaGA8yMDAzMDQwMjEyMzQ1OFowDQYJKoZIhvcNAQEFBQADgYEAfbN0TCRFKdhsmvOdUoiJ+qvygGBzDxD/VWhXYA+16AphHLIWNABR3CgHB3zWtdy2j7DJmQ/R7qKj7dUhWLSqclAiPgFtQQ1YvSJAYfEIdyHkxv4NP0LSogxrumANcDyC9yt/W9yHjD2ICPBIqCsZLuLkOHYi5DlwWe9Zm9VFwCGgggPMMIIDyDCCA8QwggKsoAMCAQICAQYwDQYJKoZIhvcNAQEFBQAwgZQxFDASBgNVBAMTC1RDUy1DQSBPQ1NQMSYwJAYJKoZIhvcNAQkBFhd0Y3MtY2FAdGNzLWNhLnRjcy5jby5pbjEMMAoGA1UEChMDVENTMQwwCgYDVQQLEwNBVEMxEjAQBgNVBAcTCUh5ZGVyYWJhZDEXMBUGA1UECBMOQW5kaHJhIHByYWRlc2gxCzAJBgNVBAYTAklOMB4XDTAyMDgyOTA3MTE0M1oXDTAzMDgyOTA3MTE0M1owgZwxCzAJBgNVBAYTAklOMRcwFQYDVQQIEw5BbmRocmEgcHJhZGVzaDESMBAGA1UEBxMJSHlkZXJhYmFkMQwwCgYDVQQKEwNUQ1MxDDAKBgNVBAsTA0FUQzEeMBwGA1UEAxMVVENTLUNBIE9DU1AgUmVzcG9uZGVyMSQwIgYJKoZIhvcNAQkBFhVvY3NwQHRjcy1jYS50Y3MuY28uaW4wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAM+XWW4caMRv46D7L6Bv8iwtKgmQu0SAybmFRJiz12qXzdvTLt8C75OdgmUomxp0+gW/4XlTPUqOMQWv463aZRv9Ust4f8MHEJh4ekP/NS9+d8vEO3P40ntQkmSMcFmtA9E1koUtQ3MSJlcs441JjbgUaVnmjDmmniQnZY4bU3tVAgMBAAGjgZowgZcwDAYDVR0TAQH/BAIwADALBgNVHQ8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwkwNgYIKwYBBQUHAQEEKjAoMCYGCCsGAQUFBzABhhpodHRwOi8vMTcyLjE5LjQwLjExMDo3NzAwLzAtBgNVHR8EJjAkMCKgIKAehhxodHRwOi8vMTcyLjE5LjQwLjExMC9jcmwuY3JsMA0GCSqGSIb3DQEBBQUAA4IBAQB6FovM3B4VDDZ15o12gnADZsIk9fTAczLlcrmXLNN4PgmqgnwF0Ymj3bD5SavDOXxbA65AZJ7rBNAguLUo+xVkgxmoBH7R2sBxjTCcr07NEadxM3HQkt0aX5XYEl8eRoifwqYAI9h0ziZfTNes8elNfb3DoPPjqq6VmMg0f0iMS4W8LjNPorjRB+kIosa1deAGPhq0eJ8yr0/s2QR2/WFD5P4aXc8IKWleklnIImS3zqiPrq6tl2Bm8DZj7vXlTOwmraSQxUwzCKwYob1yGvNOUQTqpG6jxn7jgDawHU1+WjWQe4Q34/pWeGLysxTraMa+Ug9kPe+jy/qRX2xwvKBZ");
    // Simple HTTP server used as OCSP responder
    private static final SimpleHttpServer server = new SimpleHttpServer();


    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());
        PrintTestResult.printResult(junit.textui.TestRunner.run(new TestSuite(OcspResponseManagerTest.class, "OcspResponseManager Tests")));
    }

    private static void cleanSystemProps()
    {
        System.clearProperty("ocsp.enable");
        System.clearProperty("ocsp.responderURL");
        System.clearProperty("jdk.tls.stapling.responderOverride");
        System.clearProperty("jdk.tls.stapling.responderURI");
        System.clearProperty("jdk.tls.stapling.cacheLifetime");
    }

    public void testGetOCSPResponseForRevocationCheck() throws CertificateException, NoSuchProviderException, CertPathValidatorException, IOException
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        X509Certificate interCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(issuer));
        X509Certificate finalCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(cert));

        byte[] sampleNonce = new byte[16];
        Random rand = new Random();
        rand.nextBytes(sampleNonce);
        NonceExtension nonceExt = new NonceExtension(sampleNonce);

        ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(response));
        OCSPResponse resp = OCSPResponse.getInstance(aIn.readObject());
        OcspHttpHandler ocspHttpHandler = new OcspHttpHandler(200, resp.getEncoded());

        // case ocsp.enable set to false
        System.setProperty("ocsp.enable", "false");
        OcspResponseManager.reset();
        RecoverableCertPathValidatorException softFailEx = Assert.assertThrows(RecoverableCertPathValidatorException.class, () ->
        {
            OcspResponseManager.getOCSPResponseForRevocationCheck(finalCert, interCert, Collections.emptyList(), null, helper);
        });
        assertEquals("[revocation check] OCSP disabled by \"ocsp.enable\" setting", softFailEx.getMessage());

        // revert ocsp.enable to default
        System.clearProperty("ocsp.enable");
        OcspResponseManager.reset();

        // case error when creating CertId
        CertPathValidatorException hardFailEx = Assert.assertThrows(CertPathValidatorException.class, () ->
                OcspResponseManager.getOCSPResponseForRevocationCheck(finalCert, null, Collections.emptyList(), null, helper)
        );
        assertEquals("[revocation check] Error creating CertID for certificate: " + finalCert.getSubjectX500Principal(), hardFailEx.getMessage());

        // case parent OCSP URI set and responder not available
        URI parentOcspURI = URI.create("http://localhost:8000/");
        softFailEx = Assert.assertThrows(RecoverableCertPathValidatorException.class, () ->
                OcspResponseManager.getOCSPResponseForRevocationCheck(finalCert, interCert, Collections.emptyList(), parentOcspURI, helper)
        );
        assertEquals("[revocation check] Network error while trying to retrieve OCSP response for cert: " + finalCert.getSubjectX500Principal() + " from responder URL: http://localhost:8000/", softFailEx.getMessage());

        // case parent OCSP URI set and valid response
        server.start(8000, ocspHttpHandler);
        OCSPResponse ocspResponse = OcspResponseManager.getOCSPResponseForRevocationCheck(finalCert, interCert, Collections.emptyList(), parentOcspURI, helper);
        server.stop();

        assertNotNull(ocspResponse);
        assertEquals(OCSPResponseStatus.SUCCESSFUL, ocspResponse.getResponseStatus().getIntValue());

        // case ocsp.responderURL property set but malformed URL
        System.setProperty("ocsp.responderURL", "blabla");
        OcspResponseManager.reset();
        hardFailEx = Assert.assertThrows(CertPathValidatorException.class, () ->
                OcspResponseManager.getOCSPResponseForRevocationCheck(finalCert, interCert, Collections.emptyList(), null, helper)
        );
        assertEquals("[revocation check] Misconfigured property ocsp.responderURL: blabla", hardFailEx.getMessage());

        // case ocsp.responderURL property set and valid response
        System.setProperty("ocsp.responderURL", "http://localhost:8001/");
        OcspResponseManager.reset();
        server.start(8001, ocspHttpHandler);
        ocspResponse = OcspResponseManager.getOCSPResponseForRevocationCheck(finalCert, interCert, Collections.emptyList(), null, helper);
        server.stop();

        assertNotNull(ocspResponse);
        assertEquals(OCSPResponseStatus.SUCCESSFUL, ocspResponse.getResponseStatus().getIntValue());

        // case AIA extension OCSP URI (http://localhost:30080/) set on the certificate and valid response
        System.clearProperty("ocsp.responderURL");
        OcspResponseManager.reset();
        server.start(30080, ocspHttpHandler);
        ocspResponse = OcspResponseManager.getOCSPResponseForRevocationCheck(finalCert, interCert, Collections.emptyList(), null, helper);
        server.stop();

        assertNotNull(ocspResponse);
        assertEquals(OCSPResponseStatus.SUCCESSFUL, ocspResponse.getResponseStatus().getIntValue());

        softFailEx = Assert.assertThrows(RecoverableCertPathValidatorException.class, () ->
                OcspResponseManager.getOCSPResponseForRevocationCheck(finalCert, interCert, Collections.singletonList(nonceExt), null, helper)
        );
        assertEquals("[revocation check] Network error while trying to retrieve OCSP response for cert: " + finalCert.getSubjectX500Principal() + " from responder URL: http://localhost:30080/ejbca/publicweb/status/ocsp", softFailEx.getMessage());

        cleanSystemProps();
    }

    public void testGetOCSPResponseForStapling() throws CertificateException, NoSuchProviderException, IOException, InterruptedException
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        X509Certificate interCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(issuer));
        X509Certificate finalCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(cert));

        byte[] sampleNonce = new byte[16];
        Random rand = new Random();
        rand.nextBytes(sampleNonce);
        NonceExtension nonceExt = new NonceExtension(sampleNonce);

        ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(response));
        OCSPResponse resp = OCSPResponse.getInstance(aIn.readObject());
        OcspHttpHandler ocspHttpHandler = new OcspHttpHandler(200, resp.getEncoded());

        // case error when creating CertId
        OCSPResponse response = OcspResponseManager.getOCSPResponseForStapling(finalCert, null, null, helper);
        assertNull(response);

        // case jdk.tls.stapling.responderOverride set and responder URI malformed
        System.setProperty("jdk.tls.stapling.responderOverride", "true");
        System.setProperty("jdk.tls.stapling.responderURI", "blabla");
        OcspResponseManager.reset();

        response = OcspResponseManager.getOCSPResponseForStapling(finalCert, interCert, Extensions.getInstance(null), helper);
        assertNull(response);


        // case jdk.tls.stapling.responderOverride set and responder not available
        System.setProperty("jdk.tls.stapling.responderURI", "http://localhost:8002/");
        OcspResponseManager.reset();

        response = OcspResponseManager.getOCSPResponseForStapling(finalCert, interCert, Extensions.getInstance(null), helper);
        assertNull(response);

        // case responderOverride and valid response
        server.start(8002, ocspHttpHandler);
        response = OcspResponseManager.getOCSPResponseForStapling(finalCert, interCert, Extensions.getInstance(null), helper);
        server.stop();
        assertNotNull(response);
        assertEquals(OCSPResponseStatus.SUCCESSFUL, response.getResponseStatus().getIntValue());

        // case AIA extension OCSP URI (http://localhost:30080/) set on the certificate and valid response
        System.clearProperty("jdk.tls.stapling.responderOverride");
        System.clearProperty("jdk.tls.stapling.responderURI");
        OcspResponseManager.reset();

        server.start(30080, ocspHttpHandler);
        response = OcspResponseManager.getOCSPResponseForStapling(finalCert, interCert, null, helper);
        server.stop();
        assertNotNull(response);
        assertEquals(OCSPResponseStatus.SUCCESSFUL, response.getResponseStatus().getIntValue());

        // cache check (don't start server)
        response = OcspResponseManager.getOCSPResponseForStapling(finalCert, interCert, null, helper);
        assertNotNull(response);
        assertEquals(OCSPResponseStatus.SUCCESSFUL, response.getResponseStatus().getIntValue());

        // cache skip when nonce extension found
        ASN1EncodableVector extVector = new ASN1EncodableVector();
        extVector.add(new org.bouncycastle.asn1.x509.Extension(new ASN1ObjectIdentifier(nonceExt.getId()), nonceExt.isCritical(), nonceExt.getValue()));
        response = OcspResponseManager.getOCSPResponseForStapling(finalCert, interCert, Extensions.getInstance(new DERSequence(extVector)), helper);
        assertNull(response);

        // case cache lifetime 1s (response expired)
        System.setProperty("jdk.tls.stapling.cacheLifetime", "1");
        OcspResponseManager.reset();

        server.start(30080, ocspHttpHandler);
        response = OcspResponseManager.getOCSPResponseForStapling(finalCert, interCert, null, helper);
        server.stop();
        assertNotNull(response);
        assertEquals(OCSPResponseStatus.SUCCESSFUL, response.getResponseStatus().getIntValue());
        // sleep 1s for response to become expired
        Thread.sleep(1000);
        // try to get from cache
        response = OcspResponseManager.getOCSPResponseForStapling(finalCert, interCert, null, helper);
        assertNull(response);

        // case responder available and 1 expired response in cache (test clean cache)
        server.start(30080, ocspHttpHandler);
        response = OcspResponseManager.getOCSPResponseForStapling(finalCert, interCert, null, helper);
        server.stop();
        assertNotNull(response);
        assertEquals(OCSPResponseStatus.SUCCESSFUL, response.getResponseStatus().getIntValue());

        cleanSystemProps();
    }

    private static class SimpleHttpServer
    {
        private HttpServer server;

        public void start(int port, HttpHandler handler) throws IOException
        {
            server = HttpServer.create(new InetSocketAddress(port), 0);
            server.createContext("/", handler);
            server.start();
        }

        public void stop()
        {
            server.stop(0);
        }
    }

    private static class OcspHttpHandler implements HttpHandler
    {
        private final int responseCode;
        private final byte[] responseContent;

        public OcspHttpHandler(int responseCode, byte[] responseContent)
        {
            this.responseCode = responseCode;
            this.responseContent = responseContent;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException
        {
            exchange.sendResponseHeaders(responseCode, responseContent.length);
            try (OutputStream os = exchange.getResponseBody())
            {
                os.write(responseContent);
            }
        }
    }

    private static class NonceExtension
            implements java.security.cert.Extension
    {
        private final byte[] nonce;

        NonceExtension(byte[] nonce)
        {
            this.nonce = nonce;
        }

        public String getId()
        {
            return OCSPObjectIdentifiers.id_pkix_ocsp_nonce.getId();
        }

        public boolean isCritical()
        {
            return false;
        }

        public byte[] getValue()
        {
            return nonce;
        }

        public void encode(OutputStream outputStream)
                throws IOException
        {
            outputStream.write(new org.bouncycastle.asn1.x509.Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, nonce).getEncoded());
        }
    }
}