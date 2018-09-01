package org.bouncycastle.jce.provider.test;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.x509.Certificate;
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

    public static final byte[] x25519Cert = Base64.decode(
        "MIIBLDCB36ADAgECAghWAUdKKo3DMDAFBgMrZXAwGTEXMBUGA1UEAwwOSUVURiBUZX" +
            "N0IERlbW8wHhcNMTYwODAxMTIxOTI0WhcNNDAxMjMxMjM1OTU5WjAZMRcwFQYDVQQD" +
            "DA5JRVRGIFRlc3QgRGVtbzAqMAUGAytlbgMhAIUg8AmJMKdUdIt93LQ+91oNvzoNJj" +
            "ga9OukqY6qm05qo0UwQzAPBgNVHRMBAf8EBTADAQEAMA4GA1UdDwEBAAQEAwIDCDAg" +
            "BgNVHQ4BAQAEFgQUmx9e7e0EM4Xk97xiPFl1uQvIuzswBQYDK2VwA0EAryMB/t3J5v" +
            "/BzKc9dNZIpDmAgs3babFOTQbs+BolzlDUwsPrdGxO3YNGhW7Ibz3OGhhlxXrCe1Cg" +
            "w1AH9efZBw==");

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

        Signature sig = Signature.getInstance("EDDSA", "BC");

        Certificate x25519Cert = Certificate.getInstance(EdECTest.x25519Cert);

        sig.initVerify(pub);

        sig.update(x25519Cert.getTBSCertificate().getEncoded());

        isTrue(sig.verify(x25519Cert.getSignature().getBytes()));
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new EdECTest());
    }
}
