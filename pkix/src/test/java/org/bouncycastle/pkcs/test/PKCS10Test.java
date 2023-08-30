package org.bouncycastle.pkcs.test;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.DeltaCertAttributeUtils;
import org.bouncycastle.pkcs.DeltaCertificateRequestAttributeValue;
import org.bouncycastle.pkcs.DeltaCertificateRequestAttributeValueBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.bouncycastle.test.PrintTestResult;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

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

    private byte[] emptyExtensionsReq = Base64.decode(
            "MIICVDCCATwCAQAwADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKy8\n" +
            "4oC/QPFkRBE04LIA5njEulZx/EEh+J2spnThoRwk+oycYEVKp95NSfGTAoNjTwUv\n" +
            "TdB9c1PCPE1DmgZIVLEVvouB7sZbMbLSI0d//oMO/Wr/CZmvjPGB8DID7RJs0eqO\n" +
            "gLgSuyBVrwbcSKtxH4NrNDsS5IZXCcE3xzkxMDdz72m9jvIrl2ivi+YmJ7cJo3N+\n" +
            "DBEqHZW28oytOmVo+8zhxvnHb9w26GJEOxN5zYbiIVW2vU9OfeF9te+Rhnks43Pk\n" +
            "YDDP2U4hR7q0BYrdkeWdA1ReleYyn/haeAoIVLZMANIOXobiqASKqSusVq9tLD67\n" +
            "7TAywl5AVq8GOBzlXZUCAwEAAaAPMA0GCSqGSIb3DQEJDjEAMA0GCSqGSIb3DQEB\n" +
            "CwUAA4IBAQAXck62gJw1deVOLVFAwBNVNXgJarHtDg3pauHTHvN+pSbdOTe1aRzb\n" +
            "Tt4/govtuuGZsGWlUqiglLpl6qeS7Pe9m+WJwhH5yXnJ3yvy2Lc/XkeVQ0kt8uFg\n" +
            "30UyrgKng6LDgUGFjDSiFr3dK8S/iYpDu/qpl1bWJPWmfmnIXzZWWvBdUTKlfoD9\n" +
            "/NLIWINEzHQIBXGy2uLhutYOvDq0WDGOgtdFC8my/QajaJh5lo6mM/PlmcYjK286\n" +
            "EdGSIxdME7hoW/ljA5355S820QZDkYx1tI/Y/YaY5KVOntwfDQzQiwWZ2PtpTqSK\n" +
            "KYe2Ujb362yaERCE13DJC4Us9j8OOXcW\n");
    
    public void setUp()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public void testLeaveOffEmpty()
        throws Exception
    {
        KeyFactory keyFact = KeyFactory.getInstance("RSA", "BC");
        PublicKey pubKey = keyFact.generatePublic(pubKeySpec);
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

    public void testEmptyExtRequest()
        throws Exception
    {
        JcaPKCS10CertificationRequest req = new JcaPKCS10CertificationRequest(emptyExtensionsReq);

        try
        {
            req.getRequestedExtensions();
            fail("no exception thrown");
        }
        catch (IllegalStateException e)
        {
            assertEquals("pkcs_9_at_extensionRequest present but has no value", e.getMessage());
        }
    }

    public void testBrokenRequestWithDuplicateExtension()
        throws Exception
    {

        GeneralName name1 = new GeneralName(GeneralName.dNSName, "bc1.local");
        GeneralName name2 = new GeneralName(GeneralName.dNSName, "bc2.local");


        PKCS10CertificationRequest req = new PKCS10CertificationRequest(Hex.decode(
            "30820312308201fa02010030818f310b300906035504061302415531" +
                "283026060355040a0c1f546865204c6567696f6e206f662074686520426f756e637920436173746c653112301006035504070c094d" +
                "656c626f75726e653111300f06035504080c08566963746f726961312f302d06092a864886f70d0109011620666565646261636b2d" +
                "63727970746f40626f756e6379636173746c652e6f726730820122300d06092a864886f70d01010105000382010f003082010a0282" +
                "010100b08c92" +
                "7375b27e0f4f5642b8a96cca146f8ac8174b06f3d426943d49b2a2b4c5ab440a9f5c8596962d922d968b485394bfbe772422f8c32" +
                "7799224ca9f6dd6ded47c05a9ca2f619826958f1eb63c68d81732a310c88b821c8f207292e095423552ec74ab593a13422186b732" +
                "4106c0c35ca54cc46d4913f9a2d16282fcb9e32a3e4a5f764152d5c0fa1c2ca96b4ceee3f62683b2751b5f1abccd2d56f8960a887" +
                "1c7e186048fae235c863561f754bcb95ced6f89bcdc47ce6f5790600b23d14e27e5a89edcc6c25d78588fa87df199aaab01cc6594" +
                "6546b550351dab5e39002fc743851d46f65e9459b08e00e84b3e59b1c03cf8156cd9a1220671cedeeae66d0203010001a03d303b0" +
                "6092a864886f70d01090e312e302c30140603551d11040d300b82096263312e6c6f63616c30140603551d11040d300b8209626332" +
                "2e6c6f63616c300d06092a864886f70d01010b050003820101005f1a893308777f0cdacaeb7b62bebf7440769cddc7c696fe8f086" +
                "d59244aabe6d9591de69eac0ab9aca0c574ec04262cfbbdf9491444721904296f7db45dc68e27bf13803988949caad9faa903852b" +
                "a2ad9370c8127e25b92dc8849fa5b028fcdab529fecde2f0c2531d8bc6df3bd0896524b236ec60000db091561ec00b1a3c408d08a" +
                "1458caa0acb20efb9305892dd46fd062c5ac67caf8109e3947c7619e30ff271f9b2b968620c01960f55bd18c9abae088b318b853e" +
                "a00b7a0c47e569b843dbee57b57d42d01d0c2c63c035a4aea26ae2f7f824ee112b2a78c9bb859e2ae5d035dfab1210c4af4233895" +
                "53417705b4c32aaff3d12ffad2709ea50464b90"));


        //
        // Disassemble the attributes with the duplicate extensions.
        //
        Extensions extensions = req.getRequestedExtensions();
        GeneralNames subjectAltNames = GeneralNames.fromExtensions(extensions, Extension.subjectAlternativeName);

        //
        // Check expected order and value.
        //
        GeneralName[] names = subjectAltNames.getNames();
        if (!names[0].equals(name1))
        {
            fail("expected name 1");
        }

        if (!names[1].equals(name2))
        {
            fail("expected name 2");
        }
    }

    public void testDeltaRequestAttribute()
        throws Exception
    {
        KeyPairGenerator p256Kpg = KeyPairGenerator.getInstance("EC", "BC");
        p256Kpg.initialize(new ECGenParameterSpec("P-256"));
        KeyPair p256Kp = p256Kpg.generateKeyPair();

        KeyPairGenerator dilKpg = KeyPairGenerator.getInstance("Dilithium", "BC");
        dilKpg.initialize(DilithiumParameterSpec.dilithium2);
        KeyPair dilKp = dilKpg.generateKeyPair();

        PKCS10CertificationRequestBuilder pkcs10Builder = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=Test"), p256Kp.getPublic());

        ContentSigner deltaSigner = new JcaContentSignerBuilder("Dilithium2").setProvider("BC").build(dilKp.getPrivate());

        DeltaCertificateRequestAttributeValueBuilder deltaAttrBldr = new DeltaCertificateRequestAttributeValueBuilder(
            SubjectPublicKeyInfo.getInstance(dilKp.getPublic().getEncoded()));

        deltaAttrBldr.setSignatureAlgorithm(deltaSigner.getAlgorithmIdentifier());
        deltaAttrBldr.setSubject(new X500Name("CN=Dil2 Cert Req Test"));

        DeltaCertificateRequestAttributeValue deltaAttr = deltaAttrBldr.build();

        pkcs10Builder.addAttribute(new ASN1ObjectIdentifier("2.16.840.1.114027.80.6.2"), deltaAttr);

        PKCS10CertificationRequest deltaReq = pkcs10Builder.build(deltaSigner);

        pkcs10Builder.addAttribute(new ASN1ObjectIdentifier("2.16.840.1.114027.80.6.3"), new DERBitString(deltaReq.getSignature()));

        PKCS10CertificationRequest request = pkcs10Builder.build(new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(p256Kp.getPrivate()));

        assertTrue(DeltaCertAttributeUtils.isDeltaRequestSignatureValid(request, new JcaContentVerifierProviderBuilder().setProvider("BC").build(dilKp.getPublic())));

        assertTrue(request.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(p256Kp.getPublic())));
    }


    public static void main(String args[])
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        return new BCTestSetup(new TestSuite(PKCS10Test.class));
    }
}
