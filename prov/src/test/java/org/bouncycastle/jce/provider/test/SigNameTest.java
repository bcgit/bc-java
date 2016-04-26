package org.bouncycastle.jce.provider.test;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.Signature;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTest;

public class SigNameTest
    extends SimpleTest
{
    private void checkName(String name)
        throws NoSuchProviderException, NoSuchAlgorithmException
    {
        if (!name.equals(Signature.getInstance(name, "BC").getAlgorithm()))
        {
            fail("name misatch on " + name);
        }
    }

    public void performTest()
        throws Exception
    {
        checkName("SHA1withRSA");
        checkName("SHA224withRSA");
        checkName("SHA256withRSA");
        checkName("SHA384withRSA");
        checkName("SHA512withRSA");

        checkName("SHA3-224withRSA");
        checkName("SHA3-256withRSA");
        checkName("SHA3-384withRSA");
        checkName("SHA3-512withRSA");

        checkName("MD2withRSA");
        checkName("MD4withRSA");
        checkName("MD5withRSA");
        checkName("RIPEMD160withRSA");
        checkName("RIPEMD128withRSA");
        checkName("RIPEMD256withRSA");

        checkName("SHA1withDSA");
        checkName("SHA224withDSA");
        checkName("SHA256withDSA");
        checkName("SHA384withDSA");
        checkName("SHA512withDSA");
        checkName("NONEwithDSA");
        checkName("SHA1withECDSA");
        checkName("SHA224withECDSA");
        checkName("SHA256withECDSA");
        checkName("SHA384withECDSA");
        checkName("SHA512withECDSA");
        checkName("RIPEMD160withECDSA");
        checkName("SHA1withECNR");
        checkName("SHA224withECNR");
        checkName("SHA256withECNR");
        checkName("SHA384withECNR");
        checkName("SHA512withECNR");

        checkName("SHA1withRSAandMGF1");
        checkName("SHA1withRSAandMGF1");
        checkName("SHA224withRSAandMGF1");
        checkName("SHA256withRSAandMGF1");
        checkName("SHA384withRSAandMGF1");
        checkName("SHA512withRSAandMGF1");

        checkName("GOST3411withGOST3410");
        checkName("GOST3411withECGOST3410");

        checkName("SHA1withRSA/ISO9796-2");
        checkName("MD5withRSA/ISO9796-2");
        checkName("RIPEMD160withRSA/ISO9796-2");

        checkName("RIPEMD128withRSA/X9.31");
        checkName("RIPEMD160withRSA/X9.31");
        checkName("SHA1withRSA/X9.31");
        checkName("SHA224withRSA/X9.31");
        checkName("SHA256withRSA/X9.31");
        checkName("SHA384withRSA/X9.31");
        checkName("SHA512withRSA/X9.31");
        checkName("WhirlpoolwithRSA/X9.31");
    }

    public String getName()
    {
        return "SigNameTest";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new SigNameTest());
    }
}