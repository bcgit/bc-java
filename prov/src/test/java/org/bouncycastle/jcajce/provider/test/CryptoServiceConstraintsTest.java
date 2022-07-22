package org.bouncycastle.jcajce.provider.test;

import java.security.NoSuchAlgorithmException;
import java.security.Security;

import javax.crypto.Cipher;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.constraints.BitsOfSecurityConstraint;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class CryptoServiceConstraintsTest
    extends TestCase
{
    public void setUp()
    {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    }

    public String getName()
    {
        return "CryptoServiceConstraintsTest";
    }

    public void test112bits()
        throws Exception
    {
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(112));

        try
        {
            Cipher.getInstance("ARC4", new BouncyCastleProvider());
            fail("no exception!");
        }
        catch (NoSuchAlgorithmException e)
        {
            assertEquals("No such algorithm: ARC4", e.getMessage());
        }

        try
        {
            Cipher.getInstance("DES", new BouncyCastleProvider());
            fail("no exception!");
        }
        catch (NoSuchAlgorithmException e)
        {
            assertEquals("No such algorithm: DES", e.getMessage());
        }

        Cipher.getInstance("DESede", new BouncyCastleProvider());

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    public void test128bits()
        throws Exception
    {
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(128));

        try
        {
            Cipher.getInstance("DES", new BouncyCastleProvider());
            fail("no exception!");
        }
        catch (NoSuchAlgorithmException e)
        {
            assertEquals("No such algorithm: DES", e.getMessage());
        }

        try
        {
            Cipher.getInstance("DESede", new BouncyCastleProvider());
            fail("no exception!");
        }
        catch (NoSuchAlgorithmException e)
        {
            assertEquals("No such algorithm: DESede", e.getMessage());
        }

        CryptoServicesRegistrar.setServicesConstraints(null);
    }
}
