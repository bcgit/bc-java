package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.Security;
import java.util.Enumeration;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;

// Test for "PBE" dependency issue in Oracle PKCS12.
public class PKCS12StorePBETest
    extends SimpleTest
{
    private static byte[] ks = Base64.decode(
        "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"
      + "/43iJXvlAgMBhqA=");

    public String getName()
    {
        return "PKCS12StorePBETest";
    }

    public void performTest()
        throws Exception
    {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");

        keyStore.load(new ByteArrayInputStream(ks), "password".toCharArray());

        Security.insertProviderAt(new BouncyCastleProvider(), 1);

        for (Enumeration en = keyStore.aliases(); en.hasMoreElements();)
        {
            Key key = keyStore.getKey((String)en.nextElement(), "password".toCharArray());
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new PKCS12StorePBETest());
    }
}
