package org.bouncycastle.pkix.test;

import java.math.BigInteger;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9FieldID;
import org.bouncycastle.pkix.SubjectPublicKeyInfoChecker;
import org.bouncycastle.util.encoders.Base64;

public class CheckerTest
    extends TestCase
{
    private static byte[] ecCert = Base64.decode(
        "MIIC0jCCAn2gAwIBAgIBATAKBggqhkjOPQQDAjCBjzELMAkGA1UEBhMCQVUxKDAmBgNVBAoMH1RoZSBMZWdpb24gb2YgdGhlIEJvdW5jeSBDY" +
            "XN0bGUxEjAQBgNVBAcMCU1lbGJvdXJuZTERMA8GA1UECAwIVmljdG9yaWExLzAtBgkqhkiG9w0BCQEWIGZlZWRiYWNrLWNyeXB0b0Bib3V" +
            "uY3ljYXN0bGUub3JnMB4XDTIyMDMxODAzMjYxNVoXDTIyMDMxODAzMjc1NVowgY8xCzAJBgNVBAYTAkFVMSgwJgYDVQQKDB9UaGUgTGVna" +
            "W9uIG9mIHRoZSBCb3VuY3kgQ2FzdGxlMRIwEAYDVQQHDAlNZWxib3VybmUxETAPBgNVBAgMCFZpY3RvcmlhMS8wLQYJKoZIhvcNAQkBFiB" +
            "mZWVkYmFjay1jcnlwdG9AYm91bmN5Y2FzdGxlLm9yZzCCASEwgd4GByqGSM49AgEwgdICAQEwKQYHKoZIzj0BAQIef///////////////f" +
            "///////gAAAAAAAf///////MEAEHn///////////////3///////4AAAAAAAH///////AQeawFsO9zxiUHQ1lSSFHXKcanbL7J9HTd5YYX" +
            "ClCwKBD0ED/qWPNyogWzMM7hkK+35BcPTWFc9Pyf7vTs8uaqvfevo5OkKXa5uQFTKUwugRlSzaBjOIms5/Mt7AvGuAh5//////////////" +
            "/9///+eXpqfXZBx+9FSJoiQnQsCAQEDPgAETPwiEYy2zddyrIxd6pUb8+WeIpyIWhx663xy3Zi4R5GnrzZGOb1nKh/ne4hehT13Nw/jwUx" +
            "dSvyfMub4MAoGCCqGSM49BAMCA0MAMEACHkNBhgQLlQ9c8Kv3o9xXuN8D53HsDaZLW9uDBovkpwIeeMwtBs2hflv3RsWASqKhb0LjvntYz" +
            "gA3H7sXlekX");

    byte[] rsaCert = Base64.decode(
        "MIIDXjCCAsegAwIBAgIBBzANBgkqhkiG9w0BAQQFADCBtzELMAkGA1UEBhMCQVUx"
            + "ETAPBgNVBAgTCFZpY3RvcmlhMRgwFgYDVQQHEw9Tb3V0aCBNZWxib3VybmUxGjAY"
            + "BgNVBAoTEUNvbm5lY3QgNCBQdHkgTHRkMR4wHAYDVQQLExVDZXJ0aWZpY2F0ZSBB"
            + "dXRob3JpdHkxFTATBgNVBAMTDENvbm5lY3QgNCBDQTEoMCYGCSqGSIb3DQEJARYZ"
            + "d2VibWFzdGVyQGNvbm5lY3Q0LmNvbS5hdTAeFw0wMDA2MDIwNzU2MjFaFw0wMTA2"
            + "MDIwNzU2MjFaMIG4MQswCQYDVQQGEwJBVTERMA8GA1UECBMIVmljdG9yaWExGDAW"
            + "BgNVBAcTD1NvdXRoIE1lbGJvdXJuZTEaMBgGA1UEChMRQ29ubmVjdCA0IFB0eSBM"
            + "dGQxFzAVBgNVBAsTDldlYnNlcnZlciBUZWFtMR0wGwYDVQQDExR3d3cyLmNvbm5l"
            + "Y3Q0LmNvbS5hdTEoMCYGCSqGSIb3DQEJARYZd2VibWFzdGVyQGNvbm5lY3Q0LmNv"
            + "bS5hdTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEArvDxclKAhyv7Q/Wmr2re"
            + "Gw4XL9Cnh9e+6VgWy2AWNy/MVeXdlxzd7QAuc1eOWQkGQEiLPy5XQtTY+sBUJ3AO"
            + "Rvd2fEVJIcjf29ey7bYua9J/vz5MG2KYo9/WCHIwqD9mmG9g0xLcfwq/s8ZJBswE"
            + "7sb85VU+h94PTvsWOsWuKaECAwEAAaN3MHUwJAYDVR0RBB0wG4EZd2VibWFzdGVy"
            + "QGNvbm5lY3Q0LmNvbS5hdTA6BglghkgBhvhCAQ0ELRYrbW9kX3NzbCBnZW5lcmF0"
            + "ZWQgY3VzdG9tIHNlcnZlciBjZXJ0aWZpY2F0ZTARBglghkgBhvhCAQEEBAMCBkAw"
            + "DQYJKoZIhvcNAQEEBQADgYEAotccfKpwSsIxM1Hae8DR7M/Rw8dg/RqOWx45HNVL"
            + "iBS4/3N/TO195yeQKbfmzbAA2jbPVvIvGgTxPgO1MP4ZgvgRhasaa0qCJCkWvpM4"
            + "yQf33vOiYQbpv4rTwzU8AmRlBG45WdjyNIigGV+oRc61aKCTnLq7zB8N3z1TF/bF"
            + "5/8=");

    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger SEVEN = BigInteger.valueOf(7);

    public void testECCert()
        throws Exception
    {
        SubjectPublicKeyInfo info = Certificate.getInstance(ecCert).getSubjectPublicKeyInfo();

        // check okay - no exception
        SubjectPublicKeyInfoChecker.checkInfo(info);

        AlgorithmIdentifier algId = info.getAlgorithm();
        X962Parameters x9params = X962Parameters.getInstance(algId.getParameters());
        ASN1Sequence ecParameters = ASN1Sequence.getInstance(x9params.getParameters());
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (int i = 0; i != ecParameters.size(); i++)
        {
            if (i == 1)
            {
                X9FieldID fId = X9FieldID.getInstance(ecParameters.getObjectAt(1));

                v.add(new X9FieldID(ASN1Integer.getInstance(fId.getParameters()).getPositiveValue().multiply(BigInteger.valueOf(4))));
            }
            else
            {
                v.add(ecParameters.getObjectAt(i));
            }
        }

        info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(algId.getAlgorithm(), new DERSequence(v)), info.getPublicKeyData().getBytes());

        try
        {
            SubjectPublicKeyInfoChecker.checkInfo(info);
            fail();
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("Fp q value not prime", e.getMessage());
        }
    }

    public void testRsaCert()
        throws Exception
    {
        SubjectPublicKeyInfo info = Certificate.getInstance(rsaCert).getSubjectPublicKeyInfo();

        // check okay - no exception
        SubjectPublicKeyInfoChecker.checkInfo(info);
        RSAPublicKey origKey = RSAPublicKey.getInstance(info.parsePublicKey());

        // swap so modulus is prime
        info = new SubjectPublicKeyInfo(info.getAlgorithm(), new RSAPublicKey(origKey.getPublicExponent(), origKey.getModulus()));

        try
        {
            SubjectPublicKeyInfoChecker.checkInfo(info);
            fail();
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("RSA modulus is not composite", e.getMessage());
        }

        // even modulus
        info = new SubjectPublicKeyInfo(info.getAlgorithm(), new RSAPublicKey(origKey.getModulus().multiply(TWO), origKey.getPublicExponent()));

        try
        {
            SubjectPublicKeyInfoChecker.checkInfo(info);
            fail();
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("RSA modulus is even", e.getMessage());
        }

        // introduce a small prime
        info = new SubjectPublicKeyInfo(info.getAlgorithm(), new RSAPublicKey(origKey.getModulus().multiply(SEVEN), origKey.getPublicExponent()));

        try
        {
            SubjectPublicKeyInfoChecker.checkInfo(info);
            fail();
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("RSA modulus has a small prime factor", e.getMessage());
        }

        // even exponent
        info = new SubjectPublicKeyInfo(info.getAlgorithm(), new RSAPublicKey(origKey.getModulus(), origKey.getPublicExponent().multiply(TWO)));

        try
        {
            SubjectPublicKeyInfoChecker.checkInfo(info);
            fail();
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("RSA publicExponent is even", e.getMessage());
        }
    }
}
