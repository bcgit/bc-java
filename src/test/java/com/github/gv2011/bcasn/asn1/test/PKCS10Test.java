package com.github.gv2011.bcasn.asn1.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import com.github.gv2011.bcasn.asn1.ASN1InputStream;
import com.github.gv2011.bcasn.asn1.ASN1Sequence;
import com.github.gv2011.bcasn.asn1.DEROutputStream;
import com.github.gv2011.bcasn.asn1.pkcs.CertificationRequest;
import com.github.gv2011.bcasn.util.encoders.Base64;
import com.github.gv2011.bcasn.util.test.SimpleTestResult;
import com.github.gv2011.bcasn.util.test.Test;
import com.github.gv2011.bcasn.util.test.TestResult;

public class PKCS10Test
    implements Test
{
    byte[]    req1 = Base64.decode(
                "MIHoMIGTAgEAMC4xDjAMBgNVBAMTBVRlc3QyMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNF"
            +   "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALlEt31Tzt2MlcOljvacJgzQVhmlMoqAOgqJ9Pgd3Gux"
            +   "Z7/WcIlgW4QCB7WZT21O1YoghwBhPDMcNGrHei9kHQkCAwEAAaAAMA0GCSqGSIb3DQEBBQUAA0EA"
            +   "NDEI4ecNtJ3uHwGGlitNFq9WxcoZ0djbQJ5hABMotav6gtqlrwKXY2evaIrsNwkJtNdwwH18aQDU"
            +   "KCjOuBL38Q==");

    byte[]    req2 = Base64.decode(
               "MIIB6TCCAVICAQAwgagxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRQwEgYDVQQH"
            +  "EwtTYW50YSBDbGFyYTEMMAoGA1UEChMDQUJCMVEwTwYDVQQLHEhQAAAAAAAAAG8AAAAAAAAAdwAA"
            +  "AAAAAABlAAAAAAAAAHIAAAAAAAAAIAAAAAAAAABUAAAAAAAAABxIAAAAAAAARAAAAAAAAAAxDTAL"
            +  "BgNVBAMTBGJsdWUwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBANETRZ+6occCOrFxNhfKIp4C"
            +  "mMkxwhBNb7TnnahpbM9O0r4hrBPcfYuL7u9YX/jN0YNUP+/CiT39HhSe/bikaBPDEyNsl988I8vX"
            +  "piEdgxYq/+LTgGHbjRsRYCkPtmzwBbuBldNF8bV7pu0v4UScSsExmGqqDlX1TbPU8KkPU1iTAgMB"
            +  "AAGgADANBgkqhkiG9w0BAQQFAAOBgQAFbrs9qUwh93CtETk7DeUD5HcdCnxauo1bck44snSV6MZV"
            +  "OCIGaYu1501kmhEvAtVVRr6SEHwimfQDDIjnrWwYsEr/DT6tkTZAbfRd3qUu3iKjT0H0vlUZp0hJ"
            +  "66mINtBM84uZFBfoXiWY8M3FuAnGmvy6ah/dYtJorTxLKiGkew==");

    public String getName()
    {
        return "PKCS10";
    }
    
    public TestResult pkcs10Test(
        String  testName,
        byte[]  req)
    {
        try
        {
            ByteArrayInputStream    bIn = new ByteArrayInputStream(req);
            ASN1InputStream         aIn = new ASN1InputStream(bIn);

            CertificationRequest    r = new CertificationRequest((ASN1Sequence)aIn.readObject());

            ByteArrayOutputStream    bOut = new ByteArrayOutputStream();
            DEROutputStream            dOut = new DEROutputStream(bOut);

            dOut.writeObject(r.toASN1Primitive());

            byte[]                    bytes = bOut.toByteArray();

            if (bytes.length != req.length)
            {
                return new SimpleTestResult(false, getName() + ": " + testName + " failed length test");
            }

            for (int i = 0; i != req.length; i++)
            {
                if (bytes[i] != req[i])
                {
                    return new SimpleTestResult(false, getName() + ": " + testName + " failed comparison test");
                }
            }
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": Exception - " + testName + " " + e.toString());
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }

    public TestResult perform()
    {
        TestResult  res = pkcs10Test("basic CR", req1);

        if (!res.isSuccessful())
        {
            return res;
        }

        return pkcs10Test("Universal CR", req2);
    }

    public static void main(
        String[]    args)
    {
        Test    test = new PKCS10Test();

        TestResult  result = test.perform();

        System.out.println(result);
    }
}
