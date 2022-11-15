package org.bouncycastle.jce.provider.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.Locale;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTest;

public class CertLocaleTest
    extends SimpleTest
{

    public String getName()
    {
        return "CertLocale";
    }

    public void performTest()
        throws Exception
    {
        KeyPairGenerator kpG = KeyPairGenerator.getInstance("EC", "BC");

        kpG.initialize(new ECGenParameterSpec("P-256"));

        KeyPair kp = kpG.generateKeyPair();

        Locale.setDefault(new Locale("hi", "IN"));

        X509Certificate selfSignedCert = TestUtils.createSelfSignedCert("CN=ECDSA", "SHA256withECDSA", kp);

        Date nb = selfSignedCert.getNotBefore();
        // if we get this far without an exception, we're good.
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new CertLocaleTest());
    }
}
