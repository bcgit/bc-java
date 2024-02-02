package org.bouncycastle.cert.cmp.test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Locale;
import java.util.Random;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.SubsequentMessage;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.cmp.CMSProcessableCMPCertificate;
import org.bouncycastle.cert.cmp.CertificateConfirmationContent;
import org.bouncycastle.cert.cmp.CertificateConfirmationContentBuilder;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.cert.crmf.CertificateRepMessage;
import org.bouncycastle.cert.crmf.CertificateRepMessageBuilder;
import org.bouncycastle.cert.crmf.CertificateReqMessages;
import org.bouncycastle.cert.crmf.CertificateReqMessagesBuilder;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.cert.crmf.CertificateResponse;
import org.bouncycastle.cert.crmf.CertificateResponseBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessageBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKEMEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKEMRecipientInfoGenerator;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.PBEMacCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.jcajce.JcePBMac1CalculatorBuilder;
import org.bouncycastle.pkcs.jcajce.JcePBMac1CalculatorProviderBuilder;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.bouncycastle.test.GeneralTest;
import org.bouncycastle.util.BigIntegers;

public class CMPGeneralTest
    extends GeneralTest
{
    public static void main(String[] args)
        throws Exception
    {
        CMPGeneralTest test = new CMPGeneralTest();
        test.setUp();
        //test.testNTRURequestWithDilithiumCA();
//        test.testRSAPublicKey_withJceCMSKEMKeyWrapper();
        test.testProtectedPKIMessageBuilder();
        test.testKyberRequestWithDilithiumCA();
    }


    private X509CertificateHolder testX509v3CertificateBuilder(X509v3CertificateBuilder certGen, PrivateKey issPriv, PublicKey issPub)
        throws Exception
    {
        certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(0).getEncoded());
        ContentSigner signer = new JcaContentSignerBuilder("Dilithium").build(issPriv);
        X509CertificateHolder caCert = certGen.build(signer);
        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder().build(issPub);
        assertTrue(caCert.isSignatureValid(verifier));
        return caCert;
    }

//    public void testRSAPublicKey_withJceCMSKEMKeyWrapper()
//        throws Exception
//    {
//        char[] senderMacPassword = "secret".toCharArray();
//        GeneralName sender = new GeneralName(new X500Name("CN=Kyber Subject"));
//        GeneralName recipient = new GeneralName(new X500Name("CN=NTRU Issuer"));
//        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("NTRU", "BCPQC");
//        kpGen.initialize(NTRUParameterSpec.ntruhrss701);
//        //kpGen.initialize(1024, new SecureRandom()); //
//        KeyPair kp = kpGen.generateKeyPair();
//        //X509CertificateHolder caCert = makeV3Certificate("CN=RSA Issuer", kp);
//
//        CertificateReqMessagesBuilder certReqMsgsBldr = new CertificateReqMessagesBuilder();
//
//        JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigIntegers.ONE);
//
//        certReqBuild
//            .setPublicKey(kp.getPublic())
//            .setSubject(X500Name.getInstance(sender.getName()))
//            .setProofOfPossessionSubsequentMessage(SubsequentMessage.encrCert);
//
//        certReqMsgsBldr.addRequest(certReqBuild.build());
//
//        MacCalculator senderMacCalculator = new JcePBMac1CalculatorBuilder("HmacSHA256", 256).setProvider("BC").build(senderMacPassword);
//
//        ProtectedPKIMessage message = new ProtectedPKIMessageBuilder(sender, recipient)
//            .setBody(PKIBody.TYPE_INIT_REQ, certReqMsgsBldr.build())
//            .build(senderMacCalculator);
//        CertificateReqMessages requestMessages = CertificateReqMessages.fromPKIBody(message.getBody());
//        CertificateRequestMessage senderReqMessage = requestMessages.getRequests()[0];
//        CertTemplate certTemplate = senderReqMessage.getCertTemplate();
//        //X509CertificateHolder cert = makeV3Certificate(certTemplate.getPublicKey(), certTemplate.getSubject(), kp, "CN=RSA Issuer");
//        PrivateKey issPriv = kp.getPrivate();
//        PublicKey issPub = kp.getPublic();
//
//        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
//            new X500Name("CN=RSA Issuer"),
//            BigInteger.valueOf(System.currentTimeMillis()),
//            new Date(System.currentTimeMillis()),
//            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
//            new X500Name("CN=RSA Issuer"),
//            kp.getPublic());
//
//        certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
//
//        ContentSigner signer = new JcaContentSignerBuilder("Dilithium")
//            .build(issPriv);
//
//        X509CertificateHolder cert = certGen.build(signer);
//
//        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder().build(issPub);
//
//        assertTrue(cert.isSignatureValid(verifier));
//
//        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
//        edGen.addRecipientInfoGenerator(new JceKEMRecipientInfoGenerator(senderReqMessage.getCertReqId().getEncoded(),
//            new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert).getPublicKey(), CMSAlgorithm.AES256_WRAP)
//            .setKDF(new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake256)));
//        System.out.println("test");
//    }

//    public void testNTRURequestWithDilithiumCA()
//        throws Exception
//    {
//        char[] senderMacPassword = "secret".toCharArray();
//        GeneralName sender = new GeneralName(new X500Name("CN=NTRU Subject"));
//        GeneralName recipient = new GeneralName(new X500Name("CN=Dilithium Issuer"));
//
//        KeyPairGenerator dilKpGen = KeyPairGenerator.getInstance("Dilithium", "BCPQC");
//
//        dilKpGen.initialize(DilithiumParameterSpec.dilithium2);
//
//        KeyPair dilKp = dilKpGen.generateKeyPair();
//
//        X509CertificateHolder caCert = makeV3Certificate("CN=Dilithium Issuer", dilKp);
//
//        KeyPairGenerator kybKpGen = KeyPairGenerator.getInstance("NTRU", "BCPQC");
//
//        kybKpGen.initialize(NTRUParameterSpec.ntruhrss701);
//
//        KeyPair ntruKp = kybKpGen.generateKeyPair();
//
//        // initial request
//
//        JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigIntegers.ONE);
//
//        certReqBuild
//            .setPublicKey(ntruKp.getPublic())
//            .setSubject(X500Name.getInstance(sender.getName()))
//            .setProofOfPossessionSubsequentMessage(SubsequentMessage.encrCert);
//
//        CertificateReqMessagesBuilder certReqMsgsBldr = new CertificateReqMessagesBuilder();
//
//        certReqMsgsBldr.addRequest(certReqBuild.build());
//
//        MacCalculator senderMacCalculator = new JcePBMac1CalculatorBuilder("HmacSHA256", 256).setProvider("BC").build(senderMacPassword);
//
//        ProtectedPKIMessage initMessage = new ProtectedPKIMessageBuilder(sender, recipient)
//            .setBody(PKIBody.TYPE_INIT_REQ, certReqMsgsBldr.build())
//            .build(senderMacCalculator);
//
//        // extract
//
//        assertTrue(initMessage.getProtectionAlgorithm().equals(senderMacCalculator.getAlgorithmIdentifier()));
//
//        PBEMacCalculatorProvider macCalcProvider = new JcePBMac1CalculatorProviderBuilder().setProvider("BC").build();
//
//        assertTrue(initMessage.verify(macCalcProvider, senderMacPassword));
//
//        assertEquals(PKIBody.TYPE_INIT_REQ, initMessage.getBody().getType());
//
//        CertificateReqMessages requestMessages = CertificateReqMessages.fromPKIBody(initMessage.getBody());
//        CertificateRequestMessage senderReqMessage = requestMessages.getRequests()[0];
//        CertTemplate certTemplate = senderReqMessage.getCertTemplate();
//
//        X509CertificateHolder cert = makeV3Certificate(certTemplate.getPublicKey(), certTemplate.getSubject(), dilKp, "CN=Dilithium Issuer");
//
//        // Send response with encrypted certificate
//        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
//
//        // note: use cert req ID as key ID, don't want to use issuer/serial in this case!
//
//        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
//        kpGen.initialize(1024, new SecureRandom()); //
//        KeyPair kp = kpGen.generateKeyPair();
//        edGen.addRecipientInfoGenerator(new JceKEMRecipientInfoGenerator(senderReqMessage.getCertReqId().getEncoded(),
//            kp.getPublic(), CMSAlgorithm.AES256_WRAP)
//            .setKDF(new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake256)));
//
//        CMSEnvelopedData encryptedCert = edGen.generate(
//            new CMSProcessableCMPCertificate(cert),
//            new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES192_CBC).setProvider("BC").build());
//
//        CertificateResponseBuilder certRespBuilder = new CertificateResponseBuilder(senderReqMessage.getCertReqId(), new PKIStatusInfo(PKIStatus.granted));
//
//        certRespBuilder.withCertificate(encryptedCert);
//
//        CertificateRepMessageBuilder repMessageBuilder = new CertificateRepMessageBuilder(caCert);
//
//        repMessageBuilder.addCertificateResponse(certRespBuilder.build());
//
//        ContentSigner signer = new JcaContentSignerBuilder("Dilithium").setProvider("BCPQC").build(dilKp.getPrivate());
//
//        CertificateRepMessage repMessage = repMessageBuilder.build();
//
//        ProtectedPKIMessage responsePkixMessage = new ProtectedPKIMessageBuilder(sender, recipient)
//            .setBody(PKIBody.TYPE_INIT_REP, repMessage)
//            .build(signer);
//
//        // decrypt the certificate
//
//        assertTrue(responsePkixMessage.verify(new JcaContentVerifierProviderBuilder().build(caCert)));
//
//        CertificateRepMessage certRepMessage = CertificateRepMessage.fromPKIBody(responsePkixMessage.getBody());
//
//        CertificateResponse certResp = certRepMessage.getResponses()[0];
//
//        assertEquals(true, certResp.hasEncryptedCertificate());
//
//        // this is the long-way to decrypt, for testing
//        CMSEnvelopedData receivedEnvelope = certResp.getEncryptedCertificate();
//        RecipientInformationStore recipients = receivedEnvelope.getRecipientInfos();
//        Collection c = recipients.getRecipients();
//
//        assertEquals(1, c.size());
//
//        RecipientInformation recInfo = (RecipientInformation)c.iterator().next();
//
//        assertEquals(recInfo.getKeyEncryptionAlgOID(), BCObjectIdentifiers.ntruhrss701.getId());
//
//        // Note: we don't specify the provider here as we're actually using both BC and BCPQC
//
//        byte[] recData = recInfo.getContent(new JceKEMEnvelopedRecipient(ntruKp.getPrivate()));
//
//        assertEquals(true, Arrays.equals(new CMPCertificate(cert.toASN1Structure()).getEncoded(), recData));
//
//        // this is the preferred way of recovering an encrypted certificate
//
//        CMPCertificate receivedCMPCert = certResp.getCertificate(new JceKEMEnvelopedRecipient(ntruKp.getPrivate()));
//
//        X509CertificateHolder receivedCert = new X509CertificateHolder(receivedCMPCert.getX509v3PKCert());
//
//        X509CertificateHolder caCertHolder = certRepMessage.getX509Certificates()[0];
//
//        assertEquals(true, receivedCert.isSignatureValid(new JcaContentVerifierProviderBuilder().build(caCertHolder)));
//
//        // confirmation message calculation
//
//        CertificateConfirmationContent content = new CertificateConfirmationContentBuilder()
//            .addAcceptedCertificate(cert, BigInteger.ONE)
//            .build(new JcaDigestCalculatorProviderBuilder().build());
//
//        ProtectedPKIMessage certConf = new ProtectedPKIMessageBuilder(sender, recipient)
//            .setBody(PKIBody.TYPE_CERT_CONFIRM, content)
//            .build(senderMacCalculator);
//
//        assertTrue(content.getStatusMessages()[0].isVerified(receivedCert, new JcaDigestCalculatorProviderBuilder().build()));
//        assertEquals(PKIBody.TYPE_CERT_CONFIRM, certConf.getBody().getType());
//
//        // confirmation receiving
//
//        CertificateConfirmationContent recContent = CertificateConfirmationContent.fromPKIBody(certConf.getBody());
//
//        assertTrue(recContent.getStatusMessages()[0].isVerified(receivedCert, new JcaDigestCalculatorProviderBuilder().build()));
//
////        JcaPEMWriter pOut = new JcaPEMWriter(new FileWriter("/tmp/ntru_dil_cmp/ca_cert.pem"));
////        pOut.writeObject(caCert);
////        pOut.close();
////
////        pOut = new JcaPEMWriter(new FileWriter("/tmp/ntru_dil_cmp/ntru_priv.pem"));
////        pOut.writeObject(ntruKp.getPrivate());
////        pOut.close();
////
////        pOut = new JcaPEMWriter(new FileWriter("/tmp/ntru_dil_cmp/ntru_cert.pem"));
////        pOut.writeObject(cert);
////        pOut.close();
////
////        OutputStream fOut = new FileOutputStream("/tmp/ntru_dil_cmp/cmp_message.ir");
////        fOut.write(initMessage.toASN1Structure().getEncoded());
////        fOut.close();
////
////        fOut = new FileOutputStream("/tmp/ntru_dil_cmp/cmp_message.ip");
////        fOut.write(responsePkixMessage.toASN1Structure().getEncoded());
////        fOut.close();
////
////        fOut = new FileOutputStream("/tmp/ntru_dil_cmp/cmp_message.ip");
////        fOut.write(responsePkixMessage.toASN1Structure().getEncoded());
////        fOut.close();
////
////        fOut = new FileOutputStream("/tmp/ntru_dil_cmp/cmp_message.certConf");
////        fOut.write(certConf.toASN1Structure().getEncoded());
////        fOut.close();
////
////        System.err.println(ASN1Dump.dumpAsString(receivedEnvelope.toASN1Structure()));
//    }

    public void testProtectedPKIMessageBuilder()
        throws Exception
    {
        final char[] senderMacPassword = "secret".toCharArray();
        final GeneralName sender = new GeneralName(new X500Name("CN=Kyber Subject"));
        final GeneralName recipient = new GeneralName(new X500Name("CN=Dilithium Issuer"));
        String _subDN = "CN=Dilithium Issuer";
        final CertificateReqMessagesBuilder certReqMsgsBldr = new CertificateReqMessagesBuilder();
        KeyPairGenerator kybKpGen = KeyPairGenerator.getInstance("Kyber", "BCPQC");
        KeyPairGenerator dilKpGen = KeyPairGenerator.getInstance("Dilithium", "BCPQC");
        KeyPair dilKp = dilKpGen.generateKeyPair();
        kybKpGen.initialize(KyberParameterSpec.kyber512);
        KeyPair kybKp = kybKpGen.generateKeyPair();
        JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigIntegers.ONE);
        certReqBuild
            .setPublicKey(kybKp.getPublic())
            .setSubject(X500Name.getInstance(sender.getName()))
            .setProofOfPossessionSubsequentMessage(SubsequentMessage.encrCert)
            .setIssuer(new X500Name(_subDN));
        certReqMsgsBldr.addRequest(certReqBuild.build());
        final MacCalculator senderMacCalculator = new JcePBMac1CalculatorBuilder("HmacSHA256", 256)
            .setProvider(new BouncyCastleProvider())
            .setRandom(new SecureRandom())
            .build(senderMacPassword);

        final byte[] tid = new byte[16];
        byte[] tmp = new byte[32];
        byte[] kid = new byte[24];
        byte[] nonce = new byte[48];
        byte[] senderkid = new byte[20];
        byte[] sendernonce = new byte[25];
        Random rnd = new Random();
        rnd.nextBytes(tid);
        rnd.nextBytes(tmp);
        final PKIFreeText freeText = new PKIFreeText(Arrays.toString(tmp));
        rnd.nextBytes(tmp);
        InfoTypeAndValue itav = new InfoTypeAndValue(new ASN1ObjectIdentifier("1.2.3.4.5"), new DEROctetString(tmp));
        Date time = new Date();
        rnd.nextBytes(kid);
        rnd.nextBytes(nonce);
        rnd.nextBytes(senderkid);
        rnd.nextBytes(sendernonce);
        final PKIBody body = new PKIBody(PKIBody.TYPE_INIT_REQ, certReqMsgsBldr.build().toASN1Structure());
        ProtectedPKIMessage message = new ProtectedPKIMessageBuilder(sender, recipient)
            .setBody(body)
            .setTransactionID(tid)
            .setFreeText(freeText)
            .addGeneralInfo(itav)
            .setMessageTime(time)
            .setRecipKID(kid)
            .setRecipNonce(nonce)
            .setSenderKID(senderkid)
            .setSenderNonce(sendernonce)
            .build(senderMacCalculator);
        PKIHeader header = message.getHeader();
        assertEquals(new DEROctetString(tid), header.getTransactionID());
        assertEquals(freeText, header.getFreeText());
        assertEquals(itav, header.getGeneralInfo()[0]);
        assertEquals(new ASN1GeneralizedTime(time), header.getMessageTime());
        assertEquals(new DEROctetString(kid), header.getRecipKID());
        assertEquals(new DEROctetString(nonce), header.getRecipNonce());
        assertEquals(new DEROctetString(senderkid), header.getSenderKID());
        assertEquals(new DEROctetString(sendernonce), header.getSenderNonce());

        CertificateReqMessages requestMessages = CertificateReqMessages.fromPKIBody(message.getBody());
        CertificateRequestMessage senderReqMessage = requestMessages.getRequests()[0];
        CertTemplate certTemplate = senderReqMessage.getCertTemplate();
        X509CertificateHolder cert = makeV3Certificate(certTemplate.getPublicKey(), certTemplate.getSubject(), dilKp, "CN=Dilithium Issuer");
        message = new ProtectedPKIMessageBuilder(sender, recipient)
            .setBody(body)
            .setTransactionID(tid)
            .setFreeText(freeText)
            .addGeneralInfo(itav)
            .setMessageTime(time)
            .setRecipKID(kid)
            .setRecipNonce(nonce)
            .setSenderKID(senderkid)
            .setSenderNonce(sendernonce)
            .addCMPCertificate(cert)
            .build(senderMacCalculator);
        X509CertificateHolder cert1 = message.getCertificates()[0];
        assertEquals(cert, cert1);


        testException(" does not match CMP type CertReqMessages", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                ProtectedPKIMessage message1 = new ProtectedPKIMessageBuilder(sender, recipient)
                    .setBody(PKIBody.TYPE_INIT_REP, certReqMsgsBldr.build())
                    .build(senderMacCalculator);
            }
        });

        testException("body must be set before building", "IllegalStateException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                ProtectedPKIMessage message1 = new ProtectedPKIMessageBuilder(sender, recipient)
                    .build(senderMacCalculator);
            }
        });

        // Tests for X509CertificateHolder
        testException("malformed data: ", "CertIOException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                ProtectedPKIMessage message = new ProtectedPKIMessageBuilder(sender, recipient)
                    .setBody(body)
                    .setTransactionID(tid)
                    .setFreeText(freeText)
                    .build(senderMacCalculator);
                X509CertificateHolder cert1 = new X509CertificateHolder(message.toASN1Structure().getEncoded());
            }
        });


    }

    public void testKyberRequestWithDilithiumCA()
        throws Exception
    {
        final char[] senderMacPassword = "secret".toCharArray();
        final GeneralName sender = new GeneralName(new X500Name("CN=Kyber Subject"));
        final GeneralName recipient = new GeneralName(new X500Name("CN=Dilithium Issuer"));
        KeyPairGenerator dilKpGen = KeyPairGenerator.getInstance("Dilithium", "BCPQC");
        dilKpGen.initialize(DilithiumParameterSpec.dilithium2);
        KeyPair dilKp = dilKpGen.generateKeyPair();
        String _subDN = "CN=Dilithium Issuer";
        final PrivateKey issPriv = dilKp.getPrivate();
        PublicKey issPub = dilKp.getPublic();

        // Tests for X509v3CertificateBuilder
        X509CertificateHolder caCert = testX509v3CertificateBuilder(new JcaX509v3CertificateBuilder(
            new X500Name(_subDN),
            BigInteger.valueOf(System.currentTimeMillis()),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
            new X500Name(_subDN),
            SubjectPublicKeyInfo.getInstance(dilKp.getPublic().getEncoded())), issPriv, issPub);

        caCert = testX509v3CertificateBuilder(new JcaX509v3CertificateBuilder(
            new X500Name(_subDN),
            BigInteger.valueOf(System.currentTimeMillis()),
            new Time(new Date(System.currentTimeMillis())),
            new Time(new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100))),
            new X500Name(_subDN),
            dilKp.getPublic()), issPriv, issPub);

        final X509v1CertificateBuilder v1CertGen = new JcaX509v1CertificateBuilder(
            new X500Name(_subDN),
            BigInteger.ONE,
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
            new X500Name(_subDN),
            issPub);

        // Test for DefaultSignatureAlgorithmIdentifierFinder
        testException("Unknown signature type requested: ", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new DefaultSignatureAlgorithmIdentifierFinder().find("RSA");
            }
        });
        // Test for JcaContentSignerBuilder
        // TODO testException("")

        final JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("Dilithium").setProvider("BC");

        caCert = testX509v3CertificateBuilder(new JcaX509v3CertificateBuilder(
            new JcaX509CertificateConverter().setProvider("BC")
                .getCertificate(v1CertGen.build(contentSignerBuilder.build(issPriv))),
            BigInteger.valueOf(System.currentTimeMillis()),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
            new X500Name(_subDN),
            dilKp.getPublic()), issPriv, issPub);

        // Tests for X509CertificateHolder, X509v3CertificateBuilder and CertUtils
        final X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(
            new X500Name(_subDN),
            BigInteger.valueOf(System.currentTimeMillis()),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
            Locale.getDefault(),
            new X500Name(_subDN),
            SubjectPublicKeyInfo.getInstance(dilKp.getPublic().getEncoded()));
        Random random = new Random();
        ContentSigner signer = new JcaContentSignerBuilder("Dilithium").build(issPriv);
        boolean[] subjectUniqueID = new boolean[16];
        boolean[] issuerUniqueID = new boolean[17];
        for (int i = 0; i < 16; i++)
        {
            subjectUniqueID[i] = random.nextBoolean();
            issuerUniqueID[i] = random.nextBoolean();
        }
        issuerUniqueID[16] = random.nextBoolean();
        certGen.setSubjectUniqueID(subjectUniqueID);
        certGen.setIssuerUniqueID(issuerUniqueID);
        certGen.addExtension(new Extension(Extension.basicConstraints, true, new BasicConstraints(false).getEncoded()));
        certGen.replaceExtension(Extension.basicConstraints, true, new BasicConstraints(true).getEncoded());
        certGen.replaceExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        certGen.removeExtension(Extension.basicConstraints);
        caCert = certGen.build(signer);
        assertNull(caCert.getExtension(Extension.basicConstraints));
        assertNull(caCert.getExtensions());

        // tests for JcaX509ExtensionUtils
        X509Certificate cert1 = new JcaX509CertificateConverter().setProvider(BC).getCertificate(caCert);
        assertEquals(0, JcaX509ExtensionUtils.getIssuerAlternativeNames(cert1).size());
        assertEquals(0, JcaX509ExtensionUtils.getSubjectAlternativeNames(cert1).size());

        certGen.addExtension(Extension.issuerAlternativeName, false, new GeneralNames(new GeneralName(new X500Name("CN=AU,O=Bouncy Castle,OU=Test 3"))));
        certGen.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName(new X500Name("CN=AU,O=Bouncy Castle,OU=Test 3"))));

        assertEquals(caCert.getNonCriticalExtensionOIDs(), Collections.unmodifiableSet(new HashSet()));
        assertEquals(caCert.getExtensionOIDs(), Collections.unmodifiableList(new ArrayList()));
        certGen.addExtension(new Extension(Extension.auditIdentity, false, new BasicConstraints(false).getEncoded()));

        testException("remove - extension (OID = ", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
            {
                certGen.removeExtension(Extension.basicConstraints);
            }
        });
        testException("replace - original extension (OID = ", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws IOException
            {
                certGen.replaceExtension(Extension.basicConstraints, true, new BasicConstraints(true).getEncoded());
            }
        });
        testException("malformed data: ", "CertIOException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new X509CertificateHolder(new BasicConstraints(true).getEncoded());
            }
        });


        caCert = certGen.build(signer);
        // tests for JcaX509ExtensionUtils
        cert1 = new JcaX509CertificateConverter().setProvider(BC).getCertificate(caCert);
        assertEquals(1, JcaX509ExtensionUtils.getIssuerAlternativeNames(cert1).size());
        assertEquals(1, JcaX509ExtensionUtils.getSubjectAlternativeNames(cert1).size());

        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder().build(issPub);
        assertTrue(caCert.isSignatureValid(verifier));
        assertEquals(caCert.toASN1Structure().getTBSCertificate().getIssuerUniqueId(), booleanToBitString(issuerUniqueID));
        assertEquals(caCert.toASN1Structure().getTBSCertificate().getSubjectUniqueId(), booleanToBitString(subjectUniqueID));
        assertTrue(caCert.hasExtensions());
        assertEquals(new Extension(Extension.auditIdentity, false, new BasicConstraints(false).getEncoded()),
            caCert.getExtension(Extension.auditIdentity));

        caCert = testX509v3CertificateBuilder(new JcaX509v3CertificateBuilder(
            new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider())
                .getCertificate(v1CertGen.build(contentSignerBuilder.build(issPriv))),
            BigInteger.valueOf(System.currentTimeMillis()),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
            new X500Name(_subDN),
            dilKp.getPublic()), issPriv, issPub);

        caCert = testX509v3CertificateBuilder(new JcaX509v3CertificateBuilder(
            new JcaX509CertificateConverter().setProvider("BC")
                .getCertificate(v1CertGen.build(contentSignerBuilder.build(issPriv))),
            BigInteger.valueOf(System.currentTimeMillis()),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
            new X500Principal(_subDN),
            dilKp.getPublic()), issPriv, issPub);

        //Test for JcaX509CertificateConverter
        Exception e = testException("cannot find required provider:", "ExCertificateException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws OperatorCreationException, CertificateException
            {
                new JcaX509CertificateConverter().setProvider("Null")
                    .getCertificate(v1CertGen.build(contentSignerBuilder.build(issPriv)));
            }
        });
        assertTrue(e.getCause().toString().contains("no such provider: "));

        KeyPairGenerator kybKpGen = KeyPairGenerator.getInstance("Kyber", "BCPQC");
        kybKpGen.initialize(KyberParameterSpec.kyber512);
        KeyPair kybKp = kybKpGen.generateKeyPair();
        // initial request
        final JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigIntegers.ONE);
        certReqBuild
            .setPublicKey(kybKp.getPublic())
            .setSubject(X500Name.getInstance(sender.getName()))
            .setIssuer(X500Name.getInstance(recipient.getName()))
            .setProofOfPossessionSubsequentMessage(SubsequentMessage.encrCert)
            .setIssuer(new X500Name(_subDN));
        final CertificateReqMessagesBuilder certReqMsgsBldr = new CertificateReqMessagesBuilder();
        certReqMsgsBldr.addRequest(certReqBuild.build());

        //Test for JcePBMac1CalculatorBuilder
        testException("unable to create MAC calculator:", "OperatorCreationException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws OperatorCreationException
            {
                MacCalculator senderMacCalculator = new JcePBMac1CalculatorBuilder("HmacSHA2561", 256).setProvider(new BouncyCastleProvider()).build(senderMacPassword);
            }
        });
        final MacCalculator senderMacCalculator = new JcePBMac1CalculatorBuilder("HmacSHA256", 256)
            .setProvider(new BouncyCastleProvider())
            .setSaltLength(-5)
            .setRandom(new SecureRandom())
            .build(senderMacPassword);

        ProtectedPKIMessage message = new ProtectedPKIMessageBuilder(sender, recipient)
            .setBody(PKIBody.TYPE_INIT_REQ, certReqMsgsBldr.build())
            .build(senderMacCalculator);

        assertTrue(message.getProtectionAlgorithm().equals(senderMacCalculator.getAlgorithmIdentifier()));

        // Test for JcePBMac1CalculatorProviderBuilder
        testException("protection algorithm not PB mac based", "OperatorCreationException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws OperatorCreationException
            {
                PBEMacCalculatorProvider macCalcProvider = new JcePBMac1CalculatorProviderBuilder().setProvider(new BouncyCastleProvider()).build();
                macCalcProvider.get(JcePBMac1CalculatorBuilder.PRF_SHA3_224, new char[256]);
            }
        });

        PBEMacCalculatorProvider macCalcProvider = new JcePBMac1CalculatorProviderBuilder().setProvider("BC").build();
        assertTrue(message.verify(macCalcProvider, senderMacPassword));
        assertEquals(PKIBody.TYPE_INIT_REQ, message.getBody().getType());

        // Tests for CertificateReqMessages
        testException("content of PKIBody wrong type: ", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                certReqMsgsBldr.addRequest(certReqBuild.build());
                CertificateReqMessages requestMessages = CertificateReqMessages.fromPKIBody(new PKIBody(PKIBody.TYPE_INIT_REP, certReqMsgsBldr.build().toASN1Structure()));
            }
        });

        CertificateReqMessages requestMessages = CertificateReqMessages.fromPKIBody(message.getBody());
        final CertificateRequestMessage senderReqMessage = requestMessages.getRequests()[0];
        CertTemplate certTemplate = senderReqMessage.getCertTemplate();

        final X509CertificateHolder cert = makeV3Certificate(certTemplate.getPublicKey(), certTemplate.getSubject(), dilKp, "CN=Dilithium Issuer");

        // Tests for JceKEMRecipientInfoGenerator and JceCMSKEMKeyWrapper
        testException("exception wrapping content key: ", "CMSException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
                edGen.addRecipientInfoGenerator(new JceKEMRecipientInfoGenerator(
                    new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert), CMSAlgorithm.AES256_WRAP)
                    .setKDF(new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake256))
                    .setProvider("BC")
                    .setSecureRandom(CryptoServicesRegistrar.getSecureRandom())
                    .setAlgorithmMapping(PKCSObjectIdentifiers.rsaEncryption, "RSA"));

                CMSEnvelopedData encryptedCert = edGen.generate(
                    new CMSProcessableCMPCertificate(cert),
                    new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(new BouncyCastleProvider()).build());
            }
        });


        final CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
        edGen.addRecipientInfoGenerator(new JceKEMRecipientInfoGenerator(
            new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert), CMSAlgorithm.AES256_WRAP)
            .setKDF(new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake256))
            .setProvider(new BouncyCastlePQCProvider())
            .setSecureRandom(CryptoServicesRegistrar.getSecureRandom())
            .setAlgorithmMapping(PKCSObjectIdentifiers.rsaEncryption, "RSA"));

        final CMSEnvelopedData encryptedCert = edGen.generate(
            new CMSProcessableCMPCertificate(cert),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC)
                .setProvider(new BouncyCastleProvider())
                .setSecureRandom(CryptoServicesRegistrar.getSecureRandom())
                .build());
        assertNull(encryptedCert.getUnprotectedAttributes());

        // Tests for JceCMSContentEncryptorBuilder
        testException("incorrect keySize for encryptionOID passed to builder.", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new JceCMSContentEncryptorBuilder(PKCSObjectIdentifiers.des_EDE3_CBC, 192 + 1);
            }
        });

        testException("incorrect keySize for encryptionOID passed to builder.", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new JceCMSContentEncryptorBuilder(OIWObjectIdentifiers.desCBC, 64 + 1);
            }
        });

        testException("incorrect keySize for encryptionOID passed to builder.", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new JceCMSContentEncryptorBuilder(PKCSObjectIdentifiers.id_alg_CMS3DESwrap, 192 + 1);
            }
        });

        testException("unable to process provided algorithmIdentifier: ", "CMSException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                AlgorithmIdentifier algorithmIdentifier = senderMacCalculator.getAlgorithmIdentifier();
                new JceCMSContentEncryptorBuilder(algorithmIdentifier)
                    .setProvider(new BouncyCastlePQCProvider())
                    .build();
            }
        });

        testException("unable to process provided algorithmIdentifier: ", "CMSException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                AlgorithmIdentifier algorithmIdentifier = senderMacCalculator.getAlgorithmIdentifier();
                new JceCMSContentEncryptorBuilder(algorithmIdentifier)
                    .setProvider(new BouncyCastlePQCProvider())
                    .build();
            }
        });

        testException("cannot create key generator: ", "CMSException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                CMSEnvelopedData encryptedCert = edGen.generate(
                    new CMSProcessableCMPCertificate(cert),
                    new JceCMSContentEncryptorBuilder(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_224, 0)
                        .setProvider(new BouncyCastleProvider())
                        .setSecureRandom(CryptoServicesRegistrar.getSecureRandom())
                        .build());
            }
        });

        testException("cannot create key generator: ", "CMSException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                CMSEnvelopedData encryptedCert = edGen.generate(
                    new CMSProcessableCMPCertificate(cert),
                    new JceCMSContentEncryptorBuilder(NISTObjectIdentifiers.id_aes192_GMAC, -1)
                        .setProvider(new BouncyCastleProvider())
                        .setSecureRandom(CryptoServicesRegistrar.getSecureRandom())
                        .build());
            }
        });

        // Tests for CertificateResponseBuilder
        testException("certificate in response already set", "IllegalStateException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                CertificateResponseBuilder certRespBuilder = new CertificateResponseBuilder(senderReqMessage.getCertReqId(), new PKIStatusInfo(PKIStatus.granted));
                certRespBuilder.withCertificate(encryptedCert);
                certRespBuilder.withCertificate(encryptedCert);
            }
        });

        testException("certificate in response already set", "IllegalStateException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                CertificateResponseBuilder certRespBuilder = new CertificateResponseBuilder(senderReqMessage.getCertReqId(), new PKIStatusInfo(PKIStatus.granted));
                certRespBuilder.withCertificate(cert);
                certRespBuilder.withCertificate(cert);
            }
        });

        testException("certificate in response already set", "IllegalStateException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                CertificateResponseBuilder certRespBuilder = new CertificateResponseBuilder(senderReqMessage.getCertReqId(), new PKIStatusInfo(PKIStatus.granted));
                CMPCertificate cmpCertificate = new CMPCertificate(cert.toASN1Structure());
                certRespBuilder.withCertificate(cmpCertificate);
                certRespBuilder.withCertificate(cmpCertificate);
            }
        });

        testException("response info already set", "IllegalStateException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                CertificateResponseBuilder certRespBuilder = new CertificateResponseBuilder(senderReqMessage.getCertReqId(), new PKIStatusInfo(PKIStatus.granted));
                certRespBuilder.withResponseInfo(new byte[0]);
                certRespBuilder.withResponseInfo(new byte[0]);
            }
        });

        final CertificateResponseBuilder certRespBuilder = new CertificateResponseBuilder(senderReqMessage.getCertReqId(), new PKIStatusInfo(PKIStatus.granted));

        certRespBuilder.withCertificate(encryptedCert);

        // Tests for CertificateRepMessageBuilder and CertificateRepMessage
        CertificateRepMessageBuilder repMessageBuilder1 = new CertificateRepMessageBuilder();
        CertificateRepMessage repMessage1 = repMessageBuilder1.build();
        assertTrue(repMessage1.isOnlyX509PKCertificates());
        assertNull(repMessage1.getCMPCertificates());


        CertificateRepMessageBuilder repMessageBuilder = new CertificateRepMessageBuilder(caCert);

        repMessageBuilder.addCertificateResponse(certRespBuilder.build());

        signer = new JcaContentSignerBuilder("Dilithium")
            .setProvider(new BouncyCastleProvider())
            .setSecureRandom(CryptoServicesRegistrar.getSecureRandom())
            .build(dilKp.getPrivate());

        final CertificateRepMessage repMessage = repMessageBuilder.build();
        assertTrue(repMessage.isOnlyX509PKCertificates());
        assertEquals(repMessage.getCMPCertificates()[0].getX509v3PKCert(), caCert.toASN1Structure());

        testException("content of PKIBody wrong type: ", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                CertificateRepMessage repMessage1 = CertificateRepMessage.fromPKIBody(new PKIBody(PKIBody.TYPE_CERT_CONFIRM, certReqMsgsBldr.build().toASN1Structure()));
            }
        });

        final ContentSigner finalSigner = signer;
        testException(" does not match CMP type CertRepMessage", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                ProtectedPKIMessage responsePkixMessage = new ProtectedPKIMessageBuilder(sender, recipient)
                    .setBody(PKIBody.TYPE_INIT_REQ, repMessage).build(finalSigner);
            }
        });

        testException("body must be set before building", "IllegalStateException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                ProtectedPKIMessage responsePkixMessage = new ProtectedPKIMessageBuilder(sender, recipient)
                    .build(finalSigner);
            }
        });

        ProtectedPKIMessage responsePkixMessage = new ProtectedPKIMessageBuilder(sender, recipient)
            .setBody(PKIBody.TYPE_INIT_REP, repMessage)
            .build(signer);

        // decrypt the certificate

        assertTrue(responsePkixMessage.verify(new JcaContentVerifierProviderBuilder().setProvider(new BouncyCastleProvider()).build(caCert)));

        CertificateRepMessage certRepMessage = CertificateRepMessage.fromPKIBody(responsePkixMessage.getBody());

        CertificateResponse certResp = certRepMessage.getResponses()[0];

        assertEquals(true, certResp.hasEncryptedCertificate());
        assertEquals(encryptedCert.toASN1Structure(), certResp.getEncryptedCertificate().toASN1Structure());

        // this is the long-way to decrypt, for testing
        CMSEnvelopedData receivedEnvelope = certResp.getEncryptedCertificate();

//        JcaPEMWriter pOut = new JcaPEMWriter(new FileWriter("/tmp/kyber_cms/kyber_cert_enveloped.pem"));
//        pOut.writeObject(receivedEnvelope.toASN1Structure());
//        pOut.close();
//
//        pOut = new JcaPEMWriter(new FileWriter("/tmp/kyber_cms/kyber_priv.pem"));
//        pOut.writeObject(kybKp.getPrivate());
//        pOut.close();
//
//        pOut = new JcaPEMWriter(new FileWriter("/tmp/kyber_cms/kyber_cert.pem"));
//        pOut.writeObject(cert);
//        pOut.close();
//
//        pOut = new JcaPEMWriter(new FileWriter("/tmp/kyber_cms/issuer_cert.pem"));
//        pOut.writeObject(caCert);
//        pOut.close();
//
//        System.err.println(ASN1Dump.dumpAsString(receivedEnvelope.toASN1Structure()));
        // Tests for RecipientInformationStore and RecipientInformation
        RecipientInformationStore recipients = receivedEnvelope.getRecipientInfos();
//                System.err.println(ASN1Dump.dumpAsString(ASN1Primitive.fromByteArray(receivedEnvelope.getEncoded())));

        RecipientInformation recInfo = (RecipientInformation)recipients.iterator().next();
        assertNull(recInfo.getKeyEncryptionAlgParams());
        assertNull(recInfo.getContentDigest());

        RecipientInformationStore recipients1 = new RecipientInformationStore(recInfo);
        Collection c = recipients1.getRecipients();
        assertEquals(1, c.size());

        assertEquals(recInfo.getKeyEncryptionAlgOID(), BCObjectIdentifiers.kyber512.getId());

        // Note: we don't specify the provider here as we're actually using both BC and BCPQC
//        assertEquals(recInfo.getKeyEncryptionAlgorithm(), new JceKEMEnvelopedRecipient(kybKp.getPrivate())
//            .getRecipientOperator(recInfo.getKeyEncryptionAlgorithm(), receivedEnvelope.getContentEncryptionAlgorithm(), new byte[32]));


        byte[] recData = recInfo.getContent(new JceKEMEnvelopedRecipient(kybKp.getPrivate()));

        assertEquals(true, Arrays.equals(new CMPCertificate(cert.toASN1Structure()).getEncoded(), recData));

        // this is the preferred way of recovering an encrypted certificate

        CMPCertificate receivedCMPCert = certResp.getCertificate(new JceKEMEnvelopedRecipient(kybKp.getPrivate()));

        X509CertificateHolder receivedCert = new X509CertificateHolder(receivedCMPCert.getX509v3PKCert());

        X509CertificateHolder caCertHolder = certRepMessage.getX509Certificates()[0];

        assertEquals(true, receivedCert.isSignatureValid(new JcaContentVerifierProviderBuilder().build(caCertHolder)));

        // confirmation message calculation

        final CertificateConfirmationContent content = new CertificateConfirmationContentBuilder()
            .addAcceptedCertificate(cert, BigInteger.ONE)
            .build(new JcaDigestCalculatorProviderBuilder().build());

        CertificateConfirmationContent content1 = new CertificateConfirmationContent(content.toASN1Structure());
        assertEquals(content1.toASN1Structure(), content.toASN1Structure());

        // Tests for CertificateConfirmationContent
        testException("content of PKIBody wrong type: ", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                CertificateConfirmationContent.fromPKIBody(new PKIBody(PKIBody.TYPE_INIT_REP, content.toASN1Structure()));
            }
        });

        testException(" does not match CMP type CertConfirmContent", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new ProtectedPKIMessageBuilder(sender, recipient)
                    .setBody(PKIBody.TYPE_INIT_REP, content)
                    .build(senderMacCalculator);
            }
        });

        message = new ProtectedPKIMessageBuilder(sender, recipient)
            .setBody(PKIBody.TYPE_CERT_CONFIRM, content)
            .build(senderMacCalculator);

        assertTrue(content.getStatusMessages()[0].isVerified(receivedCert, new JcaDigestCalculatorProviderBuilder().setProvider(new BouncyCastleProvider()).build()));
        assertEquals(PKIBody.TYPE_CERT_CONFIRM, message.getBody().getType());

        // confirmation receiving

        CertificateConfirmationContent recContent = CertificateConfirmationContent.fromPKIBody(message.getBody());

        assertTrue(recContent.getStatusMessages()[0].isVerified(receivedCert, new JcaDigestCalculatorProviderBuilder().build()));
    }

    private static X509CertificateHolder makeV3Certificate(SubjectPublicKeyInfo pubKey, X500Name _subDN, KeyPair issKP, String _issDN)
        throws OperatorCreationException, CertException, CertIOException
    {
        PrivateKey issPriv = issKP.getPrivate();
        PublicKey issPub = issKP.getPublic();

        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
            new X500Name(_issDN),
            BigInteger.valueOf(System.currentTimeMillis()),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
            _subDN,
            pubKey);

        certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));


        ContentSigner signer = new JcaContentSignerBuilder("Dilithium").build(issPriv);

        X509CertificateHolder certHolder = certGen.build(signer);

        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder().build(issPub);

        assertTrue(certHolder.isSignatureValid(verifier));

        return certHolder;
    }

    private static DERBitString booleanToBitString(boolean[] id)
    {
        byte[] bytes = new byte[(id.length + 7) / 8];

        for (int i = 0; i != id.length; i++)
        {
            bytes[i / 8] |= (id[i]) ? (1 << ((7 - (i % 8)))) : 0;
        }

        int pad = id.length % 8;

        if (pad == 0)
        {
            return new DERBitString(bytes);
        }
        else
        {
            return new DERBitString(bytes, 8 - pad);
        }
    }
}
