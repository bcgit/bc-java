package org.bouncycastle.jce.provider.test;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;

public class EdECTest
    extends SimpleTest
{
    private static final byte[] pubEnc = Base64.decode(
        "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=");

    private static final byte[] privEnc = Base64.decode(
        "MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC");

    private static final byte[] privWithPubEnc = Base64.decode(
        "MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC" +
            "oB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrB" +
            "Z9w7lshQhqowtrbLDFw4rXAxZuE=");

    public String getName()
    {
        return "EdEC";
    }
    
    public void performTest()
        throws Exception
    {
        KeyFactory kFact = KeyFactory.getInstance("EdDSA", "BC");

        PublicKey pub = kFact.generatePublic(new X509EncodedKeySpec(pubEnc));

        isTrue("pub failed", areEqual(pubEnc, pub.getEncoded()));

        PrivateKey priv = kFact.generatePrivate(new PKCS8EncodedKeySpec(privEnc));

        isTrue("priv failed", areEqual(privEnc, priv.getEncoded()));

        priv = kFact.generatePrivate(new PKCS8EncodedKeySpec(privWithPubEnc));

        isTrue("priv with pub failed", areEqual(privWithPubEnc, priv.getEncoded()));
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new EdECTest());
    }
}
