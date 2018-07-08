package org.bouncycastle.pkcs.test;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;

public class PKCS10Test
    extends TestCase
{
    private static final byte[] anssiPkcs10 = Base64.decode(
        "MIHLMHMCAQAwDzENMAsGA1UEAwwEYmx1YjBbMBUGByqGSM49AgEGCiqBegGB"
          + "X2WCAAEDQgAEB9POXLIasfF55GSxY9vshIIEnvv47B9jGZgZFN6VFHPvqe8G"
          + "j+6UpLjP0vvoInC8uu/X3JJJTsrgGrxbfOOG1KAAMAoGCCqGSM49BAMCA0gA"
          + "MEUCIQCgTdLV3IS5NuL9CHMDPOj6BumAQPdjzbgkGZghoY/wJAIgcEgF/2f4"
          + "5wYlIELOq18Uxksc0sOkbZm/nRXs1VX4rsM=");

     //
    // personal keys
    //
    private static final RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(
        new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
        new BigInteger("11", 16));

    private static final RSAPrivateCrtKeySpec privKeySpec = new RSAPrivateCrtKeySpec(
        new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
        new BigInteger("11", 16),
        new BigInteger("9f66f6b05410cd503b2709e88115d55daced94d1a34d4e32bf824d0dde6028ae79c5f07b580f5dce240d7111f7ddb130a7945cd7d957d1920994da389f490c89", 16),
        new BigInteger("c0a0758cdf14256f78d4708c86becdead1b50ad4ad6c5c703e2168fbf37884cb", 16),
        new BigInteger("f01734d7960ea60070f1b06f2bb81bfac48ff192ae18451d5e56c734a5aab8a5", 16),
        new BigInteger("b54bb9edff22051d9ee60f9351a48591b6500a319429c069a3e335a1d6171391", 16),
        new BigInteger("d3d83daf2a0cecd3367ae6f8ae1aeb82e9ac2f816c6fc483533d8297dd7884cd", 16),
        new BigInteger("b8f52fc6f38593dabb661d3f50f8897f8106eee68b1bce78a95b132b4e5b5d19", 16));

    public void setUp()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public void testLeaveOffEmpty()
        throws Exception
    {
        KeyFactory keyFact = KeyFactory.getInstance("RSA", "BC");
        PublicKey  pubKey = keyFact.generatePublic(pubKeySpec);
        PrivateKey privKey = keyFact.generatePrivate(privKeySpec);

        PKCS10CertificationRequestBuilder pkcs10Builder = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=Test"), pubKey);

        PKCS10CertificationRequest request = pkcs10Builder.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(privKey));

        assertEquals(0, request.getAttributes().length);
        assertNotNull(CertificationRequest.getInstance(request.getEncoded()).getCertificationRequestInfo().getAttributes());

        pkcs10Builder.setLeaveOffEmptyAttributes(true);

        request = pkcs10Builder.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(privKey));

        assertEquals(0, request.getAttributes().length);
        assertNull(CertificationRequest.getInstance(request.getEncoded()).getCertificationRequestInfo().getAttributes());

        pkcs10Builder.setLeaveOffEmptyAttributes(false);

        request = pkcs10Builder.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(privKey));

        assertEquals(0, request.getAttributes().length);
        assertNotNull(CertificationRequest.getInstance(request.getEncoded()).getCertificationRequestInfo().getAttributes());
    }

    public void testRequest()
        throws Exception
    {
        JcaPKCS10CertificationRequest req = new JcaPKCS10CertificationRequest(anssiPkcs10);

        assertTrue(req.getPublicKey().toString().startsWith("EC Public Key [9a:f5:f3:36:55:81:27:66:dd:d8:76:5a:96:6b:26:7b:0c:61:a2:94]"));
    }

    public static void main(String args[])
    {
        junit.textui.TestRunner.run(suite());
    }

    public static Test suite()
    {
        return new BCTestSetup(new TestSuite(PKCS10Test.class));
    }
}
