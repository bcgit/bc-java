package org.bouncycastle.mozilla.test;

import java.security.PublicKey;
import java.security.Security;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.mozilla.PublicKeyAndChallenge;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mozilla.SignedPublicKeyAndChallenge;
import org.bouncycastle.mozilla.jcajce.JcaSignedPublicKeyAndChallenge;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;

public class SPKACTest
    extends SimpleTest
{
    byte[] spkac = Base64.decode(
        "MIIBOjCBpDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEApne7ti0ibPhV8Iht" +
            "7Pws5iRckM7x4mtZYxEpeX5/IO8tDsBFdY86ewuY2f2KCca0oMWr43kdkZbPyzf4" +
            "CSV+0fZm9MJyNMywygZjoOCC+rS8kr0Ef31iHChhYsyejJnjw116Jnn96syhdHY6" +
            "lVD1rK0nn5ZkHjxU74gjoZu6BJMCAwEAARYAMA0GCSqGSIb3DQEBBAUAA4GBAKFL" +
            "g/luv0C7gMTI8ZKfFoSyi7Q7kiSQcmSj1WJgT56ouIRJO5NdvB/1n4GNik8VOAU0" +
            "NRztvGy3ZGqgbSav7lrxcNEvXH+dLbtS97s7yiaozpsOcEHqsBribpLOTRzYa8ci" +
            "CwkPmIiYqcby11diKLpd+W9RFYNme2v0rrbM2CyV");


    public String getName()
    {
        return "SignedPubicKeyAndChallenge";
    }

    public void spkacTest(String testName, byte[] req)
        throws Exception
    {
        SignedPublicKeyAndChallenge spkac;

        spkac = new SignedPublicKeyAndChallenge(req);

        PublicKeyAndChallenge pkac = spkac.getPublicKeyAndChallenge();
        PublicKey pubKey = spkac.getPublicKey("BC");
        ASN1Primitive obj = pkac.toASN1Primitive();
        if (obj == null)
        {
            fail("Error - " + testName + " PKAC ASN1Primitive was null.");
        }

        obj = spkac.toASN1Primitive();
        if (obj == null)
        {
            fail("Error - " + testName + " SPKAC ASN1Primitive was null.");
        }

        SubjectPublicKeyInfo spki = pkac.getSubjectPublicKeyInfo();
        if (spki == null)
        {
            fail("Error - " + testName + " SubjectPublicKeyInfo was null.");
        }

        DERIA5String challenge = pkac.getChallenge();
        // Most cases this will be a string of length zero.
        if (challenge == null)
        {
            fail("Error - " + testName + " challenge was null.");
        }

        byte[] bytes = spkac.toASN1Primitive().getEncoded(ASN1Encoding.DER);

        if (bytes.length != req.length)
        {
            fail(testName + " failed length test");
        }

        for (int i = 0; i != req.length; i++)
        {
            if (bytes[i] != req[i])
            {
                fail(testName + " failed comparison test");
            }
        }

        if (!spkac.verify("BC"))
        {
            fail(testName + " verification failed");
        }
    }

    public void spkacNewTest(String testName, byte[] req)
        throws Exception
    {
        SignedPublicKeyAndChallenge spkac;

        spkac = new SignedPublicKeyAndChallenge(req);

        PublicKeyAndChallenge pkac = spkac.getPublicKeyAndChallenge();
        PublicKey pubKey = spkac.getPublicKey("BC");
        ASN1Primitive obj = pkac.toASN1Primitive();
        if (obj == null)
        {
            fail("Error - " + testName + " PKAC ASN1Primitive was null.");
        }

        obj = spkac.toASN1Structure().toASN1Primitive();
        if (obj == null)
        {
            fail("Error - " + testName + " SPKAC ASN1Primitive was null.");
        }

        SubjectPublicKeyInfo spki = pkac.getSubjectPublicKeyInfo();
        if (spki == null)
        {
            fail("Error - " + testName + " SubjectPublicKeyInfo was null.");
        }

        DERIA5String challenge = pkac.getChallenge();
        // Most cases this will be a string of length zero.
        if (challenge == null)
        {
            fail("Error - " + testName + " challenge was null.");
        }

        byte[] bytes = spkac.toASN1Structure().getEncoded(ASN1Encoding.DER);

        if (bytes.length != req.length)
        {
            fail(testName + " failed length test");
        }

        for (int i = 0; i != req.length; i++)
        {
            if (bytes[i] != req[i])
            {
                fail(testName + " failed comparison test");
            }
        }

        if (!spkac.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(spkac.getSubjectPublicKeyInfo())))
        {
            fail(testName + " verification failed");
        }

        JcaSignedPublicKeyAndChallenge jcaSignedPublicKeyAndChallenge = new JcaSignedPublicKeyAndChallenge(req);

        if (!spkac.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(jcaSignedPublicKeyAndChallenge.getPublicKey())))
        {
            fail(testName + " verification failed");
        }
    }

    public void performTest()
        throws Exception
    {
        spkacTest("spkac", spkac);
        spkacNewTest("spkac", spkac);
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new SPKACTest());
    }
}
