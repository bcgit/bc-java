package org.bouncycastle.openpgp.test;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.util.test.SimpleTest;

public class PGPParsingTest
    extends SimpleTest
{
    public void performTest()
        throws Exception
    {
        PGPPublicKeyRingCollection pubRingCollection = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(this.getClass().getResourceAsStream("bigpub.asc")), new JcaKeyFingerprintCalculator());
    }

    public String getName()
    {
        return "PGPParsingTest";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new PGPParsingTest());
    }
}
