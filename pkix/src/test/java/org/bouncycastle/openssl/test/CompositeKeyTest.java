package org.bouncycastle.openssl.test;

import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import junit.framework.TestCase;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.spec.CompositeAlgorithmSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.Strings;

/**
 * Tests from: https://datatracker.ietf.org/doc/draft-ounsworth-pq-composite-keys/
 */
public class CompositeKeyTest
    extends TestCase
{
    private static final String genPubKey =
            "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBmDAMBgpghkgBhvprUAQBA4IBhgAwggGBMFkwEwYHKoZIzj0CAQYIKoZIzj0D\n"+
            "AQcDQgAExGPhrnuSG/fGyw1FN+l5h4p4AGRQCS0LBXnBO+djhcI6qnF2TvrQEaIY\n"+
            "GGpQT5wHS+7y5iJJ+dE5qjxcv8loRDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\n"+
            "AQoCggEBANsVQK1fcLQObL4ZYtczWbObECAFSsng0OLpRTPr9VGV3SsS/VoMRZqX\n"+
            "F+sszz6I2UcFTaMF9CwNRbWLuIBczzuhbHSjn65OuoN+Om2wsPo+okw46RTekB4a\n"+
            "d9QQvYRVzPlILUQ8NvZ4W0BKLviXTXWIggjtp/Y1pKRHKz8n35J6OmFWz4TKGNth\n"+
            "n87D28kmdwQYH5NLsDePHbfdw3AyLrPvQLlQw/hRPz/9Txf7yi9Djg9HtJ88ES6+\n"+
            "ZbfE1ZHxLYLSDt25tSL8A2pMuGMD3P81nYWO+gJ0vYV2WcRpXHRkjmliGqiCg4eB\n"+
            "mC4//tm0J4r9Ll8b/pp6xyOMI7jppVUCAwEAAQ==\n"+
            "-----END PUBLIC KEY-----\n";

    private static final String genPrivKey =
            "-----BEGIN PRIVATE KEY-----\n"+
            "MIIFHgIBADAMBgpghkgBhvprUAQBBIIFCTCCBQUwQQIBADATBgcqhkjOPQIBBggq\n"+
            "hkjOPQMBBwQnMCUCAQEEICN0ihCcgg5n8ALtk9tkQZqg/WLEm5NefMi/kdN06Z9u\n"+
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDbFUCtX3C0Dmy+\n"+
            "GWLXM1mzmxAgBUrJ4NDi6UUz6/VRld0rEv1aDEWalxfrLM8+iNlHBU2jBfQsDUW1\n"+
            "i7iAXM87oWx0o5+uTrqDfjptsLD6PqJMOOkU3pAeGnfUEL2EVcz5SC1EPDb2eFtA\n"+
            "Si74l011iIII7af2NaSkRys/J9+SejphVs+EyhjbYZ/Ow9vJJncEGB+TS7A3jx23\n"+
            "3cNwMi6z70C5UMP4UT8//U8X+8ovQ44PR7SfPBEuvmW3xNWR8S2C0g7dubUi/ANq\n"+
            "TLhjA9z/NZ2FjvoCdL2FdlnEaVx0ZI5pYhqogoOHgZguP/7ZtCeK/S5fG/6aescj\n"+
            "jCO46aVVAgMBAAECggEAFtT6LpdZuYofTxh6Mo9Jc+xfG9cxWiSx4FQLQEQBBwWl\n"+
            "TQ3nlXDd+CRy+7Fpz8yXSE2HL8w5DDY945OyIL6LYl2KXgWHaLUPvxByqmfVqd7J\n"+
            "L0RnFiOzxU9g2Zr9BUOj3v7kqM3VtI4KhIK2rnWmPu+BDckmzgP9Kpm4KhbPuAYP\n"+
            "iqUZSkxpSUsd5ALLsk9b0xjR7UEYkEpV2/vORwieEhOmPLzuXh+Px0yavkazT/vU\n"+
            "+h/rDSoLQn7v4fVsQgNdOaaOG/gHemGuuiLPJJlX5ZZ6mmsIaEjz+MNk0aJDH2po\n"+
            "KbAr4B709dTsnYgv7YtkEfSyOeMEdhMiswI1c9FpwQKBgQD6kdHmHCoeWNNvlqxU\n"+
            "v57e7ZDAXDA6WcfrypcsF0l72rI3J8oOPmFaNaCmwIH/Icz+Zy7fr2IYxVjyDjCa\n"+
            "zi8qTnj2ZNds71hUYOcq60u0TcSVrtocA4HW7NoWJqK5thNlNaa1M358cYBopGoN\n"+
            "ocS9yf10q2MBZtpF0fc5PbFf+QKBgQDf1L4cezoebbNTaN4KoapycHXxKozP2GwI\n"+
            "r15YRYjt0ZpHstdUPABQuwlL9CuL+5Q17VRiM81cUVNfFsBzKIXYb/PBC5UD+DmR\n"+
            "qGlT6v6uUWY6jifUgEjfyPxO0oJ3M6cChHR/TvpkT5SyaEwHpIH7IeXbMFcS5m4G\n"+
            "mSNBECO/PQKBgCD0CoHT1Go3Tl9PloxywwcYgT/7H9CcvCEzfJws19o1EdkVH4qu\n"+
            "A4mkoeMsUCxompgeo9iBLUqKsb7rxNKnKSbMOTZWXsqR07ENKXnIhiVJUQBKhZ7H\n"+
            "i0zjy268WAxKeNSHsMwF4K2nE7cvYE84pjI7nVy5qYSmrTAfg/8AMRKpAoGBAN/G\n"+
            "wN6WsE9Vm5BLapo0cMUC/FdFFAyEMdYpBei4dCJXiKgf+7miVypfI/dEwPitZ8rW\n"+
            "YKPhaHHgeLq7c2JuZAo0Ov2IR831MBEYz1zvtvmuNcda8iU4sCLTvLRNL9Re1pzk\n"+
            "sdfJrPn2uhH3xfNqG+1oQXZ3CMbDi8Ka/a0Bpst9AoGBAPR4p6WN0aoZlosyT6NI\n"+
            "4mqzNvLE4KBasmfoMmTJih7qCP3X4pqdgiI0SjsQQG/+utHLoJARwzhWHOZf1JKk\n"+
            "D8lSJH02cp/Znrjn5wPpfYKLphJBiKSPwyIjuFwcR1ck84ONeYq421NDqf7lXbvx\n"+
            "oMqjTPagXUpzHvwluDjtSi8+\n"+
            "-----END PRIVATE KEY-----\n";

    private static final String expPubKey =
            "-----BEGIN PUBLIC KEY-----\n"+
            "MIIBkTAFBgMqAwQDggGGADCCAYEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATE\n"+
            "Y+Gue5Ib98bLDUU36XmHingAZFAJLQsFecE752OFwjqqcXZO+tARohgYalBPnAdL\n"+
            "7vLmIkn50TmqPFy/yWhEMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n"+
            "2xVArV9wtA5svhli1zNZs5sQIAVKyeDQ4ulFM+v1UZXdKxL9WgxFmpcX6yzPPojZ\n"+
            "RwVNowX0LA1FtYu4gFzPO6FsdKOfrk66g346bbCw+j6iTDjpFN6QHhp31BC9hFXM\n"+
            "+UgtRDw29nhbQEou+JdNdYiCCO2n9jWkpEcrPyffkno6YVbPhMoY22GfzsPbySZ3\n"+
            "BBgfk0uwN48dt93DcDIus+9AuVDD+FE/P/1PF/vKL0OOD0e0nzwRLr5lt8TVkfEt\n"+
            "gtIO3bm1IvwDaky4YwPc/zWdhY76AnS9hXZZxGlcdGSOaWIaqIKDh4GYLj/+2bQn\n"+
            "iv0uXxv+mnrHI4wjuOmlVQIDAQAB\n"+
            "-----END PUBLIC KEY-----\n";

    private static final String expPrivKey = 
               "-----BEGIN PRIVATE KEY-----\n"+
               "MIIFFwIBADAFBgMqAwQEggUJMIIFBTBBAgEAMBMGByqGSM49AgEGCCqGSM49AwEH\n"+
               "BCcwJQIBAQQgI3SKEJyCDmfwAu2T22RBmqD9YsSbk158yL+R03Tpn24wggS+AgEA\n"+
               "MA0GCSqGSIb3DQEBAQUABIIEqDCCBKQCAQACggEBANsVQK1fcLQObL4ZYtczWbOb\n"+
               "ECAFSsng0OLpRTPr9VGV3SsS/VoMRZqXF+sszz6I2UcFTaMF9CwNRbWLuIBczzuh\n"+
               "bHSjn65OuoN+Om2wsPo+okw46RTekB4ad9QQvYRVzPlILUQ8NvZ4W0BKLviXTXWI\n"+
               "ggjtp/Y1pKRHKz8n35J6OmFWz4TKGNthn87D28kmdwQYH5NLsDePHbfdw3AyLrPv\n"+
               "QLlQw/hRPz/9Txf7yi9Djg9HtJ88ES6+ZbfE1ZHxLYLSDt25tSL8A2pMuGMD3P81\n"+
               "nYWO+gJ0vYV2WcRpXHRkjmliGqiCg4eBmC4//tm0J4r9Ll8b/pp6xyOMI7jppVUC\n"+
               "AwEAAQKCAQAW1Poul1m5ih9PGHoyj0lz7F8b1zFaJLHgVAtARAEHBaVNDeeVcN34\n"+
               "JHL7sWnPzJdITYcvzDkMNj3jk7IgvotiXYpeBYdotQ+/EHKqZ9Wp3skvRGcWI7PF\n"+
               "T2DZmv0FQ6Pe/uSozdW0jgqEgraudaY+74ENySbOA/0qmbgqFs+4Bg+KpRlKTGlJ\n"+
               "Sx3kAsuyT1vTGNHtQRiQSlXb+85HCJ4SE6Y8vO5eH4/HTJq+RrNP+9T6H+sNKgtC\n"+
               "fu/h9WxCA105po4b+Ad6Ya66Is8kmVfllnqaawhoSPP4w2TRokMfamgpsCvgHvT1\n"+
               "1OydiC/ti2QR9LI54wR2EyKzAjVz0WnBAoGBAPqR0eYcKh5Y02+WrFS/nt7tkMBc\n"+
               "MDpZx+vKlywXSXvasjcnyg4+YVo1oKbAgf8hzP5nLt+vYhjFWPIOMJrOLypOePZk\n"+
               "12zvWFRg5yrrS7RNxJWu2hwDgdbs2hYmorm2E2U1prUzfnxxgGikag2hxL3J/XSr\n"+
               "YwFm2kXR9zk9sV/5AoGBAN/Uvhx7Oh5ts1No3gqhqnJwdfEqjM/YbAivXlhFiO3R\n"+
               "mkey11Q8AFC7CUv0K4v7lDXtVGIzzVxRU18WwHMohdhv88ELlQP4OZGoaVPq/q5R\n"+
               "ZjqOJ9SASN/I/E7SgnczpwKEdH9O+mRPlLJoTAekgfsh5dswVxLmbgaZI0EQI789\n"+
               "AoGAIPQKgdPUajdOX0+WjHLDBxiBP/sf0Jy8ITN8nCzX2jUR2RUfiq4DiaSh4yxQ\n"+
               "LGiamB6j2IEtSoqxvuvE0qcpJsw5NlZeypHTsQ0peciGJUlRAEqFnseLTOPLbrxY\n"+
               "DEp41IewzAXgracTty9gTzimMjudXLmphKatMB+D/wAxEqkCgYEA38bA3pawT1Wb\n"+
               "kEtqmjRwxQL8V0UUDIQx1ikF6Lh0IleIqB/7uaJXKl8j90TA+K1nytZgo+FoceB4\n"+
               "urtzYm5kCjQ6/YhHzfUwERjPXO+2+a41x1ryJTiwItO8tE0v1F7WnOSx18ms+fa6\n"+
               "EffF82ob7WhBdncIxsOLwpr9rQGmy30CgYEA9HinpY3RqhmWizJPo0jiarM28sTg\n"+
               "oFqyZ+gyZMmKHuoI/dfimp2CIjRKOxBAb/660cugkBHDOFYc5l/UkqQPyVIkfTZy\n"+
               "n9meuOfnA+l9goumEkGIpI/DIiO4XBxHVyTzg415irjbU0Op/uVdu/GgyqNM9qBd\n"+
               "SnMe/CW4OO1KLz4=\n"+
               "-----END PRIVATE KEY-----\n";

    public void setUp()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public void testGenericCompositeKey()
        throws Exception
    {
        PEMParser pemParser = new PEMParser(new StringReader(genPubKey));

        SubjectPublicKeyInfo pubKey = (SubjectPublicKeyInfo)pemParser.readObject();

        pemParser = new PEMParser(new StringReader(genPrivKey));

        PrivateKeyInfo privKey = (PrivateKeyInfo)pemParser.readObject();
    }

    public void testExplicitCompositeKey()
        throws Exception
    {
        PEMParser pemParser = new PEMParser(new StringReader(expPubKey));

        SubjectPublicKeyInfo pubKey = (SubjectPublicKeyInfo)pemParser.readObject();

        pemParser = new PEMParser(new StringReader(genPrivKey));

        PrivateKeyInfo privKey = (PrivateKeyInfo)pemParser.readObject();
    }

    public void testRSAAndECCompositeGen()
        throws Exception
    {
        //
        // set up the keys
        //
        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC", "BC");

        ecKpg.initialize(new ECNamedCurveGenParameterSpec("P-256"));

        KeyPair ecKp = ecKpg.generateKeyPair();

        PrivateKey ecPriv = ecKp.getPrivate();
        PublicKey ecPub = ecKp.getPublic();

        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA", "BC");

        rsaKpg.initialize(new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4));

        KeyPair lmsKp = rsaKpg.generateKeyPair();

        PrivateKey lmsPriv = lmsKp.getPrivate();
        PublicKey lmsPub = lmsKp.getPublic();

        //
        // create the certificate - version 3
        //
        CompositeAlgorithmSpec compAlgSpec = new CompositeAlgorithmSpec.Builder()
            .add("SHA256withECDSA")
            .add("SHA256withRSA")
            .build();
        CompositePublicKey compPub = new CompositePublicKey(ecPub, lmsPub);
        CompositePrivateKey compPrivKey = new CompositePrivateKey(ecPriv, lmsPriv);

        ContentSigner sigGen = new JcaContentSignerBuilder("Composite", compAlgSpec).build(compPrivKey);

        X500Name issuerName = new X500Name("CN=Composite EC/RSA Test");
        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
            issuerName,
            BigInteger.valueOf(1),
            new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), issuerName,
            compPub);

        X509CertificateHolder ecCertHldr = certGen.build(sigGen);

        ContentVerifierProvider vProv = new JcaContentVerifierProviderBuilder()
            .build(compPub);

        assertTrue("ec multi failed", ecCertHldr.isSignatureValid(vProv));

        vProv = new JcaContentVerifierProviderBuilder().build(ecPub);

        assertTrue("ec failed", ecCertHldr.isSignatureValid(vProv));

        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(ecCertHldr);

        cert.checkValidity(new Date());

        //
        // check verifies in general
        //
        cert.verify(compPub);

        cert.verify(ecPub);      // ec key only

        cert.verify(ecPub, "BC");      // ec key only

       // cert.verify(ecPub, new BouncyCastleProvider());      // ec key only

        //
        // check verifies with contained key
        //
        cert.verify(cert.getPublicKey());

        ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
        CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");

        cert = (X509Certificate)fact.generateCertificate(bIn);

        org.bouncycastle.asn1.x509.Certificate crt = org.bouncycastle.asn1.x509.Certificate.getInstance(cert.getEncoded());

        assertTrue(MiscObjectIdentifiers.id_composite_key.equals(crt.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm()));
        assertTrue(null == crt.getSubjectPublicKeyInfo().getAlgorithm().getParameters());

        KeyFactory kFact = KeyFactory.getInstance("Composite", "BC");

        CompositePublicKey pubKey = (CompositePublicKey)kFact.generatePublic(new X509EncodedKeySpec(compPub.getEncoded()));
        CompositePrivateKey privKey = (CompositePrivateKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(compPrivKey.getEncoded()));

        assertTrue(pubKey.equals(compPub));
        assertTrue(privKey.equals(compPrivKey));

        StringWriter sWrt = new StringWriter();
        JcaPEMWriter pWrt = new JcaPEMWriter(sWrt);

        pWrt.writeObject(cert);
        pWrt.close();

        String certKeyStr = sWrt.toString();

        sWrt = new StringWriter();
        pWrt = new JcaPEMWriter(sWrt);

        pWrt.writeObject(privKey);
        pWrt.close();
        
        String privKeyStr = sWrt.toString();

        sWrt = new StringWriter();
        pWrt = new JcaPEMWriter(sWrt);

        pWrt.writeObject(pubKey);
        pWrt.close();

        String pubKeyStr = sWrt.toString();

        PEMParser pemParser = new PEMParser(new StringReader(certKeyStr));

        X509CertificateHolder certHldr = (X509CertificateHolder)pemParser.readObject();

        assertTrue(Arrays.areEqual(cert.getEncoded(), certHldr.getEncoded()));

        pemParser = new PEMParser(new StringReader(privKeyStr));

        PrivateKeyInfo privInfo = (PrivateKeyInfo)pemParser.readObject();

        assertTrue(Arrays.areEqual(privKey.getEncoded(), privInfo.getEncoded()));

        pemParser = new PEMParser(new StringReader(pubKeyStr));

        SubjectPublicKeyInfo pubInfo = (SubjectPublicKeyInfo)pemParser.readObject();

        assertTrue(Arrays.areEqual(pubKey.getEncoded(), pubInfo.getEncoded()));

//        doOutput("/tmp/comp_cert_1.pem", certKeyStr);
//        doOutput("/tmp/comp_priv_1.pem", privKeyStr);
//        doOutput("/tmp/comp_pub_1.pem", pubKeyStr);
    }

    public void testRSAAndECCompositeSignedDataGen()
        throws Exception
    {
        //
        // set up the keys
        //
        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC", "BC");

        ecKpg.initialize(new ECNamedCurveGenParameterSpec("P-256"));

        KeyPair ecKp = ecKpg.generateKeyPair();

        PrivateKey ecPriv = ecKp.getPrivate();
        PublicKey ecPub = ecKp.getPublic();

        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA", "BC");

        rsaKpg.initialize(new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4));

        KeyPair lmsKp = rsaKpg.generateKeyPair();

        PrivateKey lmsPriv = lmsKp.getPrivate();
        PublicKey lmsPub = lmsKp.getPublic();

        //
        // create the certificate - version 3
        //
        CompositeAlgorithmSpec compAlgSpec = new CompositeAlgorithmSpec.Builder()
            .add("SHA256withECDSA")
            .add("SHA256withRSA")
            .build();
        CompositePublicKey compPub = new CompositePublicKey(ecPub, lmsPub);
        CompositePrivateKey compPrivKey = new CompositePrivateKey(ecPriv, lmsPriv);

        ContentSigner sigGen = new JcaContentSignerBuilder("Composite", compAlgSpec).build(compPrivKey);

        X500Name issuerName = new X500Name("CN=Composite EC/RSA Test");
        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
            issuerName,
            BigInteger.valueOf(1),
            new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), issuerName,
            compPub);

        X509CertificateHolder ecCertHldr = certGen.build(sigGen);

        ContentVerifierProvider vProv = new JcaContentVerifierProviderBuilder()
            .build(compPub);

        assertTrue("ec multi failed", ecCertHldr.isSignatureValid(vProv));

        vProv = new JcaContentVerifierProviderBuilder().build(ecPub);

        assertTrue("ec failed", ecCertHldr.isSignatureValid(vProv));

        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(ecCertHldr);

        cert.checkValidity(new Date());

        //
        // check verifies in general
        //
        cert.verify(compPub);

        //
        // check verifies with contained key
        //
        cert.verify(cert.getPublicKey());

        ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
        CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");

        cert = (X509Certificate)fact.generateCertificate(bIn);

        org.bouncycastle.asn1.x509.Certificate crt = org.bouncycastle.asn1.x509.Certificate.getInstance(cert.getEncoded());

        assertTrue(MiscObjectIdentifiers.id_composite_key.equals(crt.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm()));
        assertTrue(null == crt.getSubjectPublicKeyInfo().getAlgorithm().getParameters());

        byte[]              data = "Hello World!".getBytes();
        List certList = new ArrayList();
        CMSTypedData msg = new CMSProcessableByteArray(data);

        certList.add(cert);

        Store certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        DigestCalculatorProvider digProvider = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
        JcaSignerInfoGeneratorBuilder signerInfoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(digProvider);

        signerInfoGeneratorBuilder.setContentDigest(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));
        
        gen.addSignerInfoGenerator(signerInfoGeneratorBuilder.build(sigGen, cert));

        gen.addCertificates(certs);

        CMSSignedData s = gen.generate(msg, true);

        s = new CMSSignedData(s.getEncoded());

        SignerInformationStore sigStore = s.getSignerInfos();
        Store certStore = s.getCertificates();

        SignerInformation sigInf = (SignerInformation)sigStore.getSigners().iterator().next();

        assertTrue(sigInf.verify(new JcaSimpleSignerInfoVerifierBuilder().build((X509CertificateHolder)certStore.getMatches(null).iterator().next())));

        StringWriter sWrt = new StringWriter();
        JcaPEMWriter pWrt = new JcaPEMWriter(sWrt);

        pWrt.writeObject(s.toASN1Structure());
        pWrt.close();

        PEMParser parser = new PEMParser(new StringReader(sWrt.toString()));

        s = new CMSSignedData((ContentInfo)parser.readObject());

        sigStore = s.getSignerInfos();
        certStore = s.getCertificates();

        sigInf = (SignerInformation)sigStore.getSigners().iterator().next();

        assertTrue(sigInf.verify(new JcaSimpleSignerInfoVerifierBuilder().build((X509CertificateHolder)certStore.getMatches(null).iterator().next())));

        //doOutput("/tmp/comp_cms_1.pem", sWrt.toString());
    }

    public void testMLDSA44andP256()
        throws Exception
    {
        //
        // set up the keys
        //
        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC", "BC");

        ecKpg.initialize(new ECNamedCurveGenParameterSpec("P-256"));

        KeyPair ecKp = ecKpg.generateKeyPair();

        PrivateKey ecPriv = ecKp.getPrivate();
        PublicKey ecPub = ecKp.getPublic();

        KeyPairGenerator rmldsaKpg = KeyPairGenerator.getInstance("ML-DSA-44", "BC");

        KeyPair mldsaKp = rmldsaKpg.generateKeyPair();

        PrivateKey mldsaPriv = mldsaKp.getPrivate();
        PublicKey mldsaPub = mldsaKp.getPublic();

        CompositePrivateKey mlecPriv = new CompositePrivateKey(IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256, mldsaPriv, ecPriv);

        StringWriter sWrt = new StringWriter();
        JcaPEMWriter pWrt = new JcaPEMWriter(sWrt);

        pWrt.writeObject(mlecPriv);

        pWrt.close();

        CompositePublicKey mlecPub = new CompositePublicKey(mldsaPub, ecPub);

        pWrt = new JcaPEMWriter(sWrt);

        pWrt.writeObject(mlecPub);

        pWrt.close();

        PEMParser pPrs = new PEMParser(new StringReader(sWrt.toString()));

        JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter().setProvider("BC");
        CompositePrivateKey prKey = (CompositePrivateKey)keyConverter.getPrivateKey((PrivateKeyInfo)pPrs.readObject());

        CompositePublicKey puKey = (CompositePublicKey)keyConverter.getPublicKey((SubjectPublicKeyInfo)pPrs.readObject());
    }

    public void testMLDSA44andEd25519()
        throws Exception
    {
        //
        // set up the keys
        //
        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("ED25519", "BC");

        KeyPair ecKp = ecKpg.generateKeyPair();

        PrivateKey ecPriv = ecKp.getPrivate();
        PublicKey ecPub = ecKp.getPublic();

        KeyPairGenerator rmldsaKpg = KeyPairGenerator.getInstance("ML-DSA-44", "BC");

        KeyPair mldsaKp = rmldsaKpg.generateKeyPair();

        PrivateKey mldsaPriv = mldsaKp.getPrivate();
        PublicKey mldsaPub = mldsaKp.getPublic();

        CompositePrivateKey mlecPriv = new CompositePrivateKey(IANAObjectIdentifiers.id_MLDSA44_Ed25519_SHA512, mldsaPriv, ecPriv);

        StringWriter sWrt = new StringWriter();
        JcaPEMWriter pWrt = new JcaPEMWriter(sWrt);

        pWrt.writeObject(mlecPriv);

        pWrt.close();

        CompositePublicKey mlecPub = new CompositePublicKey(mldsaPub, ecPub);

        pWrt = new JcaPEMWriter(sWrt);

        pWrt.writeObject(mlecPub);

        pWrt.close();

        PEMParser pPrs = new PEMParser(new StringReader(sWrt.toString()));

        JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter().setProvider("BC");
        CompositePrivateKey prKey = (CompositePrivateKey)keyConverter.getPrivateKey((PrivateKeyInfo)pPrs.readObject());

        CompositePublicKey puKey = (CompositePublicKey)keyConverter.getPublicKey((SubjectPublicKeyInfo)pPrs.readObject());
    }

    public void testMLDSA87andEd448()
        throws Exception
    {
        //
        // set up the keys
        //
        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("ED448", "BC");

        KeyPair ecKp = ecKpg.generateKeyPair();

        PrivateKey ecPriv = ecKp.getPrivate();
        PublicKey ecPub = ecKp.getPublic();

        KeyPairGenerator rmldsaKpg = KeyPairGenerator.getInstance("ML-DSA-87", "BC");

        KeyPair mldsaKp = rmldsaKpg.generateKeyPair();

        PrivateKey mldsaPriv = mldsaKp.getPrivate();
        PublicKey mldsaPub = mldsaKp.getPublic();

        CompositePrivateKey mlecPriv = new CompositePrivateKey(IANAObjectIdentifiers.id_MLDSA87_Ed448_SHAKE256, mldsaPriv, ecPriv);

        StringWriter sWrt = new StringWriter();
        JcaPEMWriter pWrt = new JcaPEMWriter(sWrt);

        pWrt.writeObject(mlecPriv);

        pWrt.close();

        CompositePublicKey mlecPub = new CompositePublicKey(mldsaPub, ecPub);

        pWrt = new JcaPEMWriter(sWrt);

        pWrt.writeObject(mlecPub);

        pWrt.close();

        PEMParser pPrs = new PEMParser(new StringReader(sWrt.toString()));

        JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter().setProvider("BC");
        CompositePrivateKey prKey = (CompositePrivateKey)keyConverter.getPrivateKey((PrivateKeyInfo)pPrs.readObject());

        CompositePublicKey puKey = (CompositePublicKey)keyConverter.getPublicKey((SubjectPublicKeyInfo)pPrs.readObject());
    }

    private static void doOutput(String fileName, String contents)
        throws IOException
    {
        FileOutputStream fOut = new FileOutputStream(fileName);
        fOut.write(Strings.toByteArray(contents));
        fOut.close();
    }
}
