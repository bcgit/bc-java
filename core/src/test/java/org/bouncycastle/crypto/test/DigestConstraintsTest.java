package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.CryptoServiceConstraintsException;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.constraints.BitsOfSecurityConstraint;
import org.bouncycastle.crypto.digests.Blake3Digest;
import org.bouncycastle.crypto.digests.CSHAKEDigest;
import org.bouncycastle.crypto.digests.DSTU7564Digest;
import org.bouncycastle.crypto.digests.MD2Digest;
import org.bouncycastle.crypto.digests.MD4Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.macs.KMAC;
import org.bouncycastle.util.test.SimpleTest;

public class DigestConstraintsTest
    extends SimpleTest
{
    public String getName()
    {
        return "DigestConstraintsTest";
    }

    public void performTest()
        throws Exception
    {
        testMD2();
        testMD4();
        testMD5();
        testSHA1();
        testSHA224();
        testSHA256();
        testSHA384();
        testSHA512();
        testSHA3();
        testDSTU7564();
        testBlake3();
    }

    private void testMD2()
    {
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(128));

        try
        {
            new MD2Digest();
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 128 bits of security only 64", e.getMessage());
        }

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testMD4()
    {
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(128));

        try
        {
            new MD4Digest();
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 128 bits of security only 64", e.getMessage());
        }

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testMD5()
    {
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(128));

        try
        {
            new MD5Digest();
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 128 bits of security only 64", e.getMessage());
        }

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testSHA1()
    {
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(128));

        try
        {
            new SHA1Digest();
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 128 bits of security only 80", e.getMessage());
        }

        new SHA1Digest(CryptoServicePurpose.PRF);

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testSHA224()
    {
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(192));

        try
        {
            new SHA224Digest();
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 192 bits of security only 112", e.getMessage());
        }

        new SHA224Digest(CryptoServicePurpose.PRF);

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testSHA256()
    {
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(192));

        try
        {
            new SHA256Digest();
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 192 bits of security only 128", e.getMessage());
        }

        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(256));

        new SHA256Digest(CryptoServicePurpose.PRF);

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testSHA384()
    {
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(256));

        try
        {
            new SHA384Digest();
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 256 bits of security only 192", e.getMessage());
        }

        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(256));

        new SHA384Digest(CryptoServicePurpose.PRF);

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testSHA512()
    {
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(256));

        new SHA512Digest();
        new SHA512Digest(CryptoServicePurpose.PRF);

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testSHA3()
    {
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(256));

        try
        {
            new SHA3Digest(224);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 256 bits of security only 112", e.getMessage());
        }

        try
        {
            new SHA3Digest(256);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 256 bits of security only 128", e.getMessage());
        }

        try
        {
            new SHA3Digest(384);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 256 bits of security only 192", e.getMessage());
        }

        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(256));

        new SHA3Digest(256, CryptoServicePurpose.PRF);
        new SHA3Digest(384, CryptoServicePurpose.PRF);

        try
        {
            new SHA3Digest(224, CryptoServicePurpose.PRF);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 256 bits of security only 224", e.getMessage());
        }

        try
        {
            new SHAKEDigest(128);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only 128", e.getMessage());
        }

        try
        {
            new CSHAKEDigest(128, new byte[0], new byte[0]);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only 128", e.getMessage());
        }

        try
        {
            new KMAC(128, new byte[0]);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only 128", e.getMessage());
        }

        try
        {
            new SHAKEDigest(128, CryptoServicePurpose.PRF);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only 128", e.getMessage());
        }

        new SHA3Digest(512);
        new SHAKEDigest(256);
        new CSHAKEDigest(256, new byte[0], new byte[0]);
        new KMAC(256, new byte[0]);

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testDSTU7564()
    {
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(256));

        try
        {
            new DSTU7564Digest(256);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only 128", e.getMessage());
        }
        try
        {
            new DSTU7564Digest(384);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only 192", e.getMessage());
        }

        new DSTU7564Digest(512);

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testBlake3()
    {
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(256));

        try
        {
            new Blake3Digest(224);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 256 bits of security only 112", e.getMessage());
        }

        try
        {
            new Blake3Digest(256);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 256 bits of security only 128", e.getMessage());
        }

        try
        {
            new Blake3Digest(384);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 256 bits of security only 192", e.getMessage());
        }

        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(256));

        new Blake3Digest(256, CryptoServicePurpose.PRF);
        new Blake3Digest(384, CryptoServicePurpose.PRF);

        try
        {
            new Blake3Digest(224, CryptoServicePurpose.PRF);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 256 bits of security only 224", e.getMessage());
        }

        new Blake3Digest(512);

        CryptoServicesRegistrar.setServicesConstraints(null);
    }
    
    public static void main(
        String[] args)
    {
        runTest(new DigestConstraintsTest());
    }
}
