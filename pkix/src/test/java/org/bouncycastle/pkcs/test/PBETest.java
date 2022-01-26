package org.bouncycastle.pkcs.test;

import java.security.Security;

import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.pkcs.jcajce.JcePBMac1CalculatorBuilder;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class PBETest
    extends TestCase
{
    public void setUp()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public void testPBESHA256()
        throws Exception
    {
        MacCalculator pbCalculator = new JcePBMac1CalculatorBuilder("HmacSHA256", 256)
            .setIterationCount(1)
            .setSalt(Strings.toByteArray("salt"))
            .setPrf(JcePBMac1CalculatorBuilder.PRF_SHA256)
            .setProvider("BC").build("passwd".toCharArray());

        assertEquals("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc", Hex.toHexString((byte[])pbCalculator.getKey().getRepresentation()));

    }
}
