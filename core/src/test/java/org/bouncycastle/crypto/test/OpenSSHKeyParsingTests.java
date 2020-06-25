package org.bouncycastle.crypto.test;

import java.io.StringReader;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.signers.DSASigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.util.OpenSSHPrivateKeyUtil;
import org.bouncycastle.crypto.util.OpenSSHPublicKeyUtil;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.test.SimpleTest;

public class OpenSSHKeyParsingTests
    extends SimpleTest
{
    private static SecureRandom secureRandom = new SecureRandom();


    public static void main(
        String[] args)
    {
        runTest(new OpenSSHKeyParsingTests());
    }


    public void testDSA()
        throws Exception
    {
        CipherParameters pubSpec = OpenSSHPublicKeyUtil.parsePublicKey(Base64.decode("AAAAB3NzaC1kc3MAAACBAJBB5+S4kZZYZLswaQ/zm3GM7YWmHsumwo/Xxu+z6Cg2l5PUoiBBZ4ET9EhhQuL2ja/zrCMCi0ZwiSRuSp36ayPrHLbNJb3VdOuJg8xExRa6F3YfVZfcTPUEKh6FU72fI31HrQmi4rpyHnWxL/iDX496ZG2Hdq6UkPISQpQwj4TtAAAAFQCP9TXcVahR/2rpfEhvdXR0PfhbRwAAAIBdXzAVqoOtb9zog6lNF1cGS1S06W9W/clvuwq2xF1s3bkoI/xUbFSc0IAPsGl2kcB61PAZqcop50lgpvYzt8cq/tbqz3ypq1dCQ0xdmJHj975QsRFax+w6xQ0kgpBhwcS2EOizKb+C+tRzndGpcDSoSMuVXp9i4wn5pJSTZxAYFQAAAIEAhQZc687zYxrEDR/1q6m4hw5GFxuVvLsC+bSHtMF0c11Qy4IPg7mBeP7K5Kq4WyJPtmZhuc5Bb12bJQR6qgd1uLn692fe1UK2kM6eWXBzhlzZ54BslfSKHGNN4qH+ln3Zaf/4rpKE7fvoinkrgkOZmj0PMx9D6wlpHKkXMUxeXtc="));

        CipherParameters privSpec = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(new PemReader(new StringReader("-----BEGIN DSA PRIVATE KEY-----\n" +
            "MIIBuwIBAAKBgQCQQefkuJGWWGS7MGkP85txjO2Fph7LpsKP18bvs+goNpeT1KIg\n" +
            "QWeBE/RIYULi9o2v86wjAotGcIkkbkqd+msj6xy2zSW91XTriYPMRMUWuhd2H1WX\n" +
            "3Ez1BCoehVO9nyN9R60JouK6ch51sS/4g1+PemRth3aulJDyEkKUMI+E7QIVAI/1\n" +
            "NdxVqFH/aul8SG91dHQ9+FtHAoGAXV8wFaqDrW/c6IOpTRdXBktUtOlvVv3Jb7sK\n" +
            "tsRdbN25KCP8VGxUnNCAD7BpdpHAetTwGanKKedJYKb2M7fHKv7W6s98qatXQkNM\n" +
            "XZiR4/e+ULERWsfsOsUNJIKQYcHEthDosym/gvrUc53RqXA0qEjLlV6fYuMJ+aSU\n" +
            "k2cQGBUCgYEAhQZc687zYxrEDR/1q6m4hw5GFxuVvLsC+bSHtMF0c11Qy4IPg7mB\n" +
            "eP7K5Kq4WyJPtmZhuc5Bb12bJQR6qgd1uLn692fe1UK2kM6eWXBzhlzZ54BslfSK\n" +
            "HGNN4qH+ln3Zaf/4rpKE7fvoinkrgkOZmj0PMx9D6wlpHKkXMUxeXtcCFELnLOJ8\n" +
            "D0akSCUFY/iDLo/KnOIH\n" +
            "-----END DSA PRIVATE KEY-----\n")).readPemObject().getContent());

        DSASigner signer = new DSASigner();
        signer.init(true, privSpec);

        byte[] originalMessage = new byte[10];
        secureRandom.nextBytes(originalMessage);

        BigInteger[] rs = signer.generateSignature(originalMessage);

        signer.init(false, pubSpec);

        isTrue("DSA test", signer.verifySignature(originalMessage, rs[0], rs[1]));

    }


    public void testECDSA_curvesFromSSHKeyGen()
        throws Exception
    {

        String[][] pairs = new String[][]{
            {
                "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBbxKE+/DXstQZmwH7Wso8SUt8LvYoMQpxN/7INC0lMn7mNCbxJcSOCfucBuWOrdoFyFZUkGli2mzKj3hJlcPiI=",
                "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
                    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS\n" +
                    "1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQQW8ShPvw17LUGZsB+1rKPElLfC72KD\n" +
                    "EKcTf+yDQtJTJ+5jQm8SXEjgn7nAbljq3aBchWVJBpYtpsyo94SZXD4iAAAAuKFclDShXJ\n" +
                    "Q0AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBbxKE+/DXstQZmw\n" +
                    "H7Wso8SUt8LvYoMQpxN/7INC0lMn7mNCbxJcSOCfucBuWOrdoFyFZUkGli2mzKj3hJlcPi\n" +
                    "IAAAAhAP4L/ciGBDF4HoQSvMaKM8svW4Ss0uYi7HkZ1sn/zCe0AAAAHW1lZ2Fud29vZHNA\n" +
                    "dHljaGUtMzI2NS5nYXRld2F5AQI=\n" +
                    "-----END OPENSSH PRIVATE KEY-----\n"
            },
            {
                "AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBOT0Cc/zauJsOWo/0P0sMNeyFI5Enz3+lKJtjWXQD7DpFgZmG5Ise8IXR5/ot7fo0kWlYQrye/uSmNmWBuDvOpBCHOnyR6Kaej36qoOO/gwbH+mezSYXSxCTA9Qb8VzxLA==",
                "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
                    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAiAAAABNlY2RzYS\n" +
                    "1zaGEyLW5pc3RwMzg0AAAACG5pc3RwMzg0AAAAYQTk9AnP82ribDlqP9D9LDDXshSORJ89\n" +
                    "/pSibY1l0A+w6RYGZhuSLHvCF0ef6Le36NJFpWEK8nv7kpjZlgbg7zqQQhzp8keimno9+q\n" +
                    "qDjv4MGx/pns0mF0sQkwPUG/Fc8SwAAADorZ3naK2d52gAAAATZWNkc2Etc2hhMi1uaXN0\n" +
                    "cDM4NAAAAAhuaXN0cDM4NAAAAGEE5PQJz/Nq4mw5aj/Q/Sww17IUjkSfPf6Uom2NZdAPsO\n" +
                    "kWBmYbkix7whdHn+i3t+jSRaVhCvJ7+5KY2ZYG4O86kEIc6fJHopp6Pfqqg47+DBsf6Z7N\n" +
                    "JhdLEJMD1BvxXPEsAAAAMQDLno+rINnY7/Ht1WmSGZYJ3EMPtysbxuBnQFEL4USa3kyAb1\n" +
                    "QMR6+jtqraKtE7kLwAAAAdbWVnYW53b29kc0B0eWNoZS0zMjY1LmdhdGV3YXkBAg==\n" +
                    "-----END OPENSSH PRIVATE KEY-----\n"
            },
            {
                "AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBADXE/q1WSR002vRI+tiPLpdRjzeymSk+RjD7ZIC9CndqLmI0rhTMh5xReAzved12BH9lQJIGIw4YoIQDudsMbRUsQEjFvbFzSXLJBYWdZf8Voa/97/R9w/i8bKUMUPP0disypZlGdQn5+XvzHG6bhX2Qr9aJacGFZoVHugF/M8QyC+GyA==",
                "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
                    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAArAAAABNlY2RzYS\n" +
                    "1zaGEyLW5pc3RwNTIxAAAACG5pc3RwNTIxAAAAhQQA1xP6tVkkdNNr0SPrYjy6XUY83spk\n" +
                    "pPkYw+2SAvQp3ai5iNK4UzIecUXgM73nddgR/ZUCSBiMOGKCEA7nbDG0VLEBIxb2xc0lyy\n" +
                    "QWFnWX/FaGv/e/0fcP4vGylDFDz9HYrMqWZRnUJ+fl78xxum4V9kK/WiWnBhWaFR7oBfzP\n" +
                    "EMgvhsgAAAEgs+rbdbPq23UAAAATZWNkc2Etc2hhMi1uaXN0cDUyMQAAAAhuaXN0cDUyMQ\n" +
                    "AAAIUEANcT+rVZJHTTa9Ej62I8ul1GPN7KZKT5GMPtkgL0Kd2ouYjSuFMyHnFF4DO953XY\n" +
                    "Ef2VAkgYjDhighAO52wxtFSxASMW9sXNJcskFhZ1l/xWhr/3v9H3D+LxspQxQ8/R2KzKlm\n" +
                    "UZ1Cfn5e/McbpuFfZCv1olpwYVmhUe6AX8zxDIL4bIAAAAQgCM8ojULpNk3UhBZhPfK+Tw\n" +
                    "QjT9MHU0OTi4twvKPAE0vOLQ/C1g9AMlspyKxS2NKx2gxxXISowFGNL6Jkx9198ElQAAAB\n" +
                    "1tZWdhbndvb2RzQHR5Y2hlLTMyNjUuZ2F0ZXdheQECAwQF\n" +
                    "-----END OPENSSH PRIVATE KEY-----\n"
            }
        };


        for (int i = 0; i != pairs.length; i++)
        {
            String[] pair = pairs[i];

            CipherParameters pubSpec = OpenSSHPublicKeyUtil.parsePublicKey(
                Base64.decode(pair[0]));

            CipherParameters privSpec = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(
                new PemReader(
                    new StringReader(pair[1])).readPemObject().getContent());

            ECDSASigner signer = new ECDSASigner();
            signer.init(true, privSpec);

            byte[] originalMessage = new byte[10];
            secureRandom.nextBytes(originalMessage);

            BigInteger[] rs = signer.generateSignature(originalMessage);

            signer.init(false, pubSpec);

            isTrue("ECDSA test", signer.verifySignature(originalMessage, rs[0], rs[1]));

            //
            // Test encode
            //


            CipherParameters recoveredPubKey = OpenSSHPublicKeyUtil.parsePublicKey(OpenSSHPublicKeyUtil.encodePublicKey((AsymmetricKeyParameter)pubSpec));
            CipherParameters recoveredPrivateKey = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(OpenSSHPrivateKeyUtil.encodePrivateKey((AsymmetricKeyParameter)privSpec));

            signer = new ECDSASigner();
            signer.init(true, privSpec);

            originalMessage = new byte[10];
            secureRandom.nextBytes(originalMessage);

            rs = signer.generateSignature(originalMessage);

            signer.init(false, pubSpec);

            isTrue("ECDSA test post encoded / decode", signer.verifySignature(originalMessage, rs[0], rs[1]));
        }

    }


    public void testECDSA()
        throws Exception
    {
        CipherParameters pubSpec = OpenSSHPublicKeyUtil.parsePublicKey(Base64.decode("AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHq5qxGqnh93Gpbj2w1Avx1UwBl6z5bZC3Viog1yNHDZYcV6Da4YQ3i0/hN7xY7sUy9dNF6g16tJSYXQQ4tvO3g="));

        CipherParameters privSpec = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(new PemReader(new StringReader("-----BEGIN EC PRIVATE KEY-----\n" +
            "MHcCAQEEIHeg/+m02j6nr4bO8ubfbzhs0fqOjiuIoWbvGnVg+FmpoAoGCCqGSM49\n" +
            "AwEHoUQDQgAEermrEaqeH3caluPbDUC/HVTAGXrPltkLdWKiDXI0cNlhxXoNrhhD\n" +
            "eLT+E3vFjuxTL100XqDXq0lJhdBDi287eA==\n" +
            "-----END EC PRIVATE KEY-----\n")).readPemObject().getContent());

        ECDSASigner signer = new ECDSASigner();
        signer.init(true, privSpec);

        byte[] originalMessage = new byte[10];
        secureRandom.nextBytes(originalMessage);

        BigInteger[] rs = signer.generateSignature(originalMessage);

        signer.init(false, pubSpec);

        isTrue("ECDSA test", signer.verifySignature(originalMessage, rs[0], rs[1]));

    }


    public void testED25519()
        throws Exception
    {

        CipherParameters pubSpec = OpenSSHPublicKeyUtil.parsePublicKey(Base64.decode("AAAAC3NzaC1lZDI1NTE5AAAAIM4CaV7WQcy0lht0hclgXf4Olyvzvv2fnUvQ3J8IYsWF"));

        CipherParameters privSpec = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(new PemReader(new StringReader("-----BEGIN OPENSSH PRIVATE KEY-----\n" +
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n" +
            "QyNTUxOQAAACDOAmle1kHMtJYbdIXJYF3+Dpcr8779n51L0NyfCGLFhQAAAKBTr4PvU6+D\n" +
            "7wAAAAtzc2gtZWQyNTUxOQAAACDOAmle1kHMtJYbdIXJYF3+Dpcr8779n51L0NyfCGLFhQ\n" +
            "AAAED4BTHeR3YD7CFQqusztfL5K+YSD4mRGLBwb7jHiXxIJM4CaV7WQcy0lht0hclgXf4O\n" +
            "lyvzvv2fnUvQ3J8IYsWFAAAAG21lZ2Fud29vZHNAdHljaGUtMzI2NS5sb2NhbAEC\n" +
            "-----END OPENSSH PRIVATE KEY-----\n")).readPemObject().getContent());

        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, privSpec);

        byte[] originalMessage = new byte[10];
        secureRandom.nextBytes(originalMessage);
        signer.update(originalMessage, 0, originalMessage.length);

        byte[] sig = signer.generateSignature();

        signer.init(false, pubSpec);

        signer.update(originalMessage, 0, originalMessage.length);


        isTrue("ED25519Signer test", signer.verifySignature(sig));

    }


    public void testFailures()
        throws Exception
    {
        byte[] blob = new PemReader(new StringReader("-----BEGIN OPENSSH PRIVATE KEY-----\n" +
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n" +
            "QyNTUxOQAAACDOAmle1kHMtJYbdIXJYF3+Dpcr8779n51L0NyfCGLFhQAAAKBTr4PvU6+D\n" +
            "7wAAAAtzc2gtZWQyNTUxOQAAACDOAmle1kHMtJYbdIXJYF3+Dpcr8779n51L0NyfCGLFhQ\n" +
            "AAAED4BTHeR3YD7CFQqusztfL5K+YSD4mRGLBwb7jHiXxIJM4CaV7WQcy0lht0hclgXf4O\n" +
            "lyvzvv2fnUvQ3J8IYsWFAAAAG21lZ2Fud29vZHNAdHljaGUtMzI2NS5sb2NhbAEC\n" +
            "-----END OPENSSH PRIVATE KEY-----\n")).readPemObject().getContent();


        //
        // Altering the check value.
        //

        blob[98] ^= 1;

        try
        {
            CipherParameters privSpec = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(blob);
            fail("Change should trigger failure.");
        }
        catch (IllegalStateException iles)
        {
            isEquals("Check value mismatch ", iles.getMessage(), "private key check values are not the same");
        }


        //
        // Altering the cipher name.
        //


        blob = new PemReader(new StringReader("-----BEGIN OPENSSH PRIVATE KEY-----\n" +
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n" +
            "QyNTUxOQAAACDOAmle1kHMtJYbdIXJYF3+Dpcr8779n51L0NyfCGLFhQAAAKBTr4PvU6+D\n" +
            "7wAAAAtzc2gtZWQyNTUxOQAAACDOAmle1kHMtJYbdIXJYF3+Dpcr8779n51L0NyfCGLFhQ\n" +
            "AAAED4BTHeR3YD7CFQqusztfL5K+YSD4mRGLBwb7jHiXxIJM4CaV7WQcy0lht0hclgXf4O\n" +
            "lyvzvv2fnUvQ3J8IYsWFAAAAG21lZ2Fud29vZHNAdHljaGUtMzI2NS5sb2NhbAEC\n" +
            "-----END OPENSSH PRIVATE KEY-----\n")).readPemObject().getContent();


        blob[19] = (byte)'C';

        try
        {
            CipherParameters privSpec = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(blob);
            fail("Change should trigger failure.");
        }
        catch (IllegalStateException iles)
        {
            isEquals("enc keys not supported ", iles.getMessage(), "encrypted keys not supported");
        }
    }

    public String getName()
    {
        return "OpenSSHParsing";
    }

    public void performTest()
        throws Exception
    {
        testECDSA_curvesFromSSHKeyGen();
        testDSA();
        testECDSA();
        testRSA();
        testED25519();
        testFailures();
    }

    public void testRSA()
        throws Exception
    {
        CipherParameters pubSpec = OpenSSHPublicKeyUtil.parsePublicKey(Base64.decode("AAAAB3NzaC1yc2EAAAADAQABAAAAgQDvh2BophdIp8ojwGZQR0FQ/awowXnV24nAPm+/na8MOUrdySNhOnlek4LAZl82/+Eu2t21XD6hQUiHKAj6XaNFBthTuss7Cz/tA348DLEMHD9wUtT0FXVmsxqN4BfusunbcULxxVWG2z8FvqeaGgc/Unkp9y7/kyf54pPUCBcClw=="));

        CipherParameters privSpec = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(new PemReader(new StringReader("-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIICXgIBAAKBgQDvh2BophdIp8ojwGZQR0FQ/awowXnV24nAPm+/na8MOUrdySNh\n" +
            "Onlek4LAZl82/+Eu2t21XD6hQUiHKAj6XaNFBthTuss7Cz/tA348DLEMHD9wUtT0\n" +
            "FXVmsxqN4BfusunbcULxxVWG2z8FvqeaGgc/Unkp9y7/kyf54pPUCBcClwIDAQAB\n" +
            "AoGBAOMXYEoXHgAeREE9CkOWKtDUkEJbnF0rNSB0kZIDt5BJSTeYmNh3jdYi2FX9\n" +
            "OMx2MFIx4v0tJZvQvyiUxl5IJJ9ZJsYUWF+6VbcTVwYYfdVzZzP2TNyGmF9/ADZW\n" +
            "wBehqP04uRlYjt94kqb4HoOKF3gJ3LC4uW9xcEltTBeHWCfhAkEA/2biF5St9/Ya\n" +
            "540E4zu/FKPsxLSaT8LWCo9+X7IqIzlBQCB4GjM+nZeTm7eZOkfAFZoxwfiNde/9\n" +
            "qleXXf6B2QJBAPAW+jDBC3QF4/g8n9cDxm/A3ICmcOFSychLSrydk9ZyRPbTRyQC\n" +
            "YlC2mf/pCrO/yO7h189BXyQ3PXOEhnujce8CQQD7gDy0K90EiH0F94AQpA0OLj5B\n" +
            "lfc/BAXycEtpwPBtrzvqAg9C/aNzXIgmly10jqNAoo7NDA2BTcrlq0uLa8xBAkBl\n" +
            "7Hs+I1XnZXDIO4Rn1VRysN9rRj15ipnbDAuoUwUl7tDUMBFteg2e0kZCW/6NHIgC\n" +
            "0aG6fLgVOdY+qi4lYtfFAkEAqqiBgEgSrDmnJLTm6j/Pv1mBA6b9bJbjOqomrDtr\n" +
            "AWTXe+/kSCv/jYYdpNA/tDgAwEmtkWWEie6+SwJB5cXXqg==\n" +
            "-----END RSA PRIVATE KEY-----\n")).readPemObject().getContent());


        byte[] originalMessage = new byte[10];
        secureRandom.nextBytes(originalMessage);

        originalMessage[0] |= 1;

        RSAEngine rsaEngine = new RSAEngine();
        rsaEngine.init(true, privSpec);

        byte[] ct = rsaEngine.processBlock(originalMessage, 0, originalMessage.length);

        rsaEngine.init(false, pubSpec);
        byte[] result = rsaEngine.processBlock(ct, 0, ct.length);

        isTrue("Result did not match original message", Arrays.areEqual(originalMessage, result));

    }
}
