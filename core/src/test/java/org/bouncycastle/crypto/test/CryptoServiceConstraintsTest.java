package org.bouncycastle.crypto.test;

import java.util.Collections;

import org.bouncycastle.crypto.CryptoServiceConstraintsException;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.constraints.BitsOfSecurityConstraint;
import org.bouncycastle.crypto.constraints.LegacyBitsOfSecurityConstraint;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class CryptoServiceConstraintsTest
    extends SimpleTest
{
    public String getName()
    {
        return "CryptoServiceConstraintsTest";
    }

    public void performTest()
        throws Exception
    {
        test112bits();
        test128bits();
        testLegacy128bits();
    }

    private void test112bits()
    {
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(112));

        try
        {
            new RC4Engine();
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 112 bits of security only 20", e.getMessage());
        }

        // try with exception for RC4/ARC4
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(112, Collections.singleton("ARC4")));

        new RC4Engine();

        try
        {
            new DESEngine();
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 112 bits of security only 56", e.getMessage());
        }

        new DESedeEngine();

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void test128bits()
    {
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(128));

        try
        {
            new DESedeEngine();
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 128 bits of security only 112", e.getMessage());
        }

        // add exception for DESede
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(128, Collections.singleton("DESede")));

        new DESedeEngine();

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testLegacy128bits()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(128));

        DESedeEngine eng = new DESedeEngine();
        KeyParameter dKey = new KeyParameter(Hex.decode("01020304050607080102030405060708"));

        try
        {
            eng.init(true, dKey);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 128 bits of security only 80", e.getMessage());
        }

        eng.init(false, dKey);     // this should work as we are decrypting

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    public static void main(
        String[] args)
    {
        runTest(new CryptoServiceConstraintsTest());
    }
}
