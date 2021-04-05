package org.bouncycastle.asn1.test;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.isismtt.ocsp.RequestedCertificate;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.util.encoders.Base64;

public class RequestedCertificateUnitTest
    extends ASN1UnitTest
{
   byte[]  certBytes = Base64.decode(
           "MIIBWzCCAQYCARgwDQYJKoZIhvcNAQEEBQAwODELMAkGA1UEBhMCQVUxDDAKBgNV"
         + "BAgTA1FMRDEbMBkGA1UEAxMSU1NMZWF5L3JzYSB0ZXN0IENBMB4XDTk1MDYxOTIz"
         + "MzMxMloXDTk1MDcxNzIzMzMxMlowOjELMAkGA1UEBhMCQVUxDDAKBgNVBAgTA1FM"
         + "RDEdMBsGA1UEAxMUU1NMZWF5L3JzYSB0ZXN0IGNlcnQwXDANBgkqhkiG9w0BAQEF"
         + "AANLADBIAkEAqtt6qS5GTxVxGZYWa0/4u+IwHf7p2LNZbcPBp9/OfIcYAXBQn8hO"
         + "/Re1uwLKXdCjIoaGs4DLdG88rkzfyK5dPQIDAQABMAwGCCqGSIb3DQIFBQADQQAE"
         + "Wc7EcF8po2/ZO6kNCwK/ICH6DobgLekA5lSLr5EvuioZniZp5lFzAw4+YzPQ7XKJ"
         + "zl9HYIMxATFyqSiD9jsx");

    public String getName()
    {
        return "RequestedCertificate";
    }

    public void performTest()
        throws Exception
    {
        int type = 1;
        byte[] certOctets = new byte[20];
        Certificate cert = Certificate.getInstance(certBytes);

        RequestedCertificate requested = new RequestedCertificate(type, certOctets);

        checkConstruction(requested, type, certOctets, null);

        requested = new RequestedCertificate(cert);

        checkConstruction(requested, RequestedCertificate.certificate, null, cert);

        requested = RequestedCertificate.getInstance(null);

        if (requested != null)
        {
            fail("null getInstance() failed.");
        }

        try
        {
            RequestedCertificate.getInstance(new Object());

            fail("getInstance() failed to detect bad object.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void checkConstruction(
        RequestedCertificate requested,
        int type,
        byte[] certOctets,
        Certificate cert)
        throws IOException
    {
        checkValues(requested, type, certOctets, cert);

        requested = RequestedCertificate.getInstance(requested);

        checkValues(requested, type, certOctets, cert);

        ASN1InputStream aIn = new ASN1InputStream(requested.toASN1Primitive().getEncoded());

        Object obj = aIn.readObject();

        requested = RequestedCertificate.getInstance(obj);

        checkValues(requested, type, certOctets, cert);
    }

    private void checkValues(
        RequestedCertificate requested,
        int type,
        byte[] certOctets,
        Certificate cert)
        throws IOException
    {
        checkMandatoryField("certType", type, requested.getType());

        if (requested.getType() == RequestedCertificate.certificate)
        {
            checkMandatoryField("certificate", cert.getEncoded(), requested.getCertificateBytes());
        }
        else
        {
            checkMandatoryField("certificateOctets", certOctets, requested.getCertificateBytes());
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new RequestedCertificateUnitTest());
    }
}
