package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class PrivateKeyInfoTest
    extends SimpleTest
{
    private static final byte[] priv = Base64.decode(
        "MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC");

    private static final byte[] privWithPub = Base64.decode(
        "MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC" +
            "oB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrB" +
            "Z9w7lshQhqowtrbLDFw4rXAxZuE=");


    public String getName()
    {
        return "PrivateKeyInfoTest";
    }

    // a structure too short, or with a version too large for an int, is refused as malformed, rather than
    // running out of elements or overflowing on the way
    private void malformedTest()
    {
        byte[][] encodings = {
            Hex.decode("3000"),                                     // SEQUENCE {}
            Hex.decode("3003020100"),                               // version only
            // SEQUENCE { INTEGER 0x40000006096086, SEQUENCE { OID 1.2.3 }, OCTET STRING {} }
            Hex.decode("3011" + "020740000006096086" + "300406022a03" + "0400"),
        };
        String[] messages = { "bad sequence size: 0", "bad sequence size: 1", "invalid version for private key info" };
        for (int i = 0; i != encodings.length; i++)
        {
            try
            {
                PrivateKeyInfo.getInstance(encodings[i]);
                fail("malformed PrivateKeyInfo " + i + " accepted");
            }
            catch (IllegalArgumentException e)
            {
                isEquals(messages[i], e.getMessage());
            }
        }
    }

    public void performTest()
        throws Exception
    {
        malformedTest();

        PrivateKeyInfo privInfo1 = PrivateKeyInfo.getInstance(priv);

        isTrue(!privInfo1.hasPublicKey());

        PrivateKeyInfo privInfo2 = new PrivateKeyInfo(privInfo1.getPrivateKeyAlgorithm(), privInfo1.parsePrivateKey());

        isTrue("enc 1 failed", areEqual(priv, privInfo2.getEncoded()));

        privInfo1 = PrivateKeyInfo.getInstance(privWithPub);

        isTrue(privInfo1.hasPublicKey());

        privInfo2 = new PrivateKeyInfo(privInfo1.getPrivateKeyAlgorithm(), privInfo1.parsePrivateKey(), privInfo1.getAttributes(), privInfo1.getPublicKeyData().getOctets());

        isTrue("enc 2 failed", areEqual(privWithPub, privInfo2.getEncoded()));
    }

    public static void main(
        String[]    args)
    {
        runTest(new PrivateKeyInfoTest());
    }
}
