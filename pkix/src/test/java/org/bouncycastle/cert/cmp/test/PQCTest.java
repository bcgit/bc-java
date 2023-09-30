package org.bouncycastle.cert.cmp.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;

import junit.framework.TestCase;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.SubsequentMessage;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
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
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKEMEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKEMRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.PBEMacCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.jcajce.JcePBMac1CalculatorBuilder;
import org.bouncycastle.pkcs.jcajce.JcePBMac1CalculatorProviderBuilder;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.BIKEParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.CMCEParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.HQCParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.NTRUParameterSpec;
import org.bouncycastle.util.BigIntegers;

public class PQCTest
    extends TestCase
{
    public void setUp()
    {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
    }

    public void tearDown()
    {

    }

    public void testKyberRequestWithDilithiumCA()
        throws Exception
    {
        char[] senderMacPassword = "secret".toCharArray();
        GeneralName sender = new GeneralName(new X500Name("CN=Kyber Subject"));
        GeneralName recipient = new GeneralName(new X500Name("CN=Dilithium Issuer"));

        KeyPairGenerator dilKpGen = KeyPairGenerator.getInstance("Dilithium", "BCPQC");

        dilKpGen.initialize(DilithiumParameterSpec.dilithium2);

        KeyPair dilKp = dilKpGen.generateKeyPair();

        X509CertificateHolder caCert = makeV3Certificate("CN=Dilithium Issuer", dilKp);

        KeyPairGenerator kybKpGen = KeyPairGenerator.getInstance("Kyber", "BCPQC");

        kybKpGen.initialize(KyberParameterSpec.kyber512);

        KeyPair kybKp = kybKpGen.generateKeyPair();

        // initial request

        JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigIntegers.ONE);

        certReqBuild
            .setPublicKey(kybKp.getPublic())
            .setSubject(X500Name.getInstance(sender.getName()))
            .setProofOfPossessionSubsequentMessage(SubsequentMessage.encrCert);

        CertificateReqMessagesBuilder certReqMsgsBldr = new CertificateReqMessagesBuilder();

        certReqMsgsBldr.addRequest(certReqBuild.build());

        MacCalculator senderMacCalculator = new JcePBMac1CalculatorBuilder("HmacSHA256", 256).setProvider("BC").build(senderMacPassword);

        ProtectedPKIMessage message = new ProtectedPKIMessageBuilder(sender, recipient)
            .setBody(PKIBody.TYPE_INIT_REQ, certReqMsgsBldr.build())
            .build(senderMacCalculator);

        // extract

        assertTrue(message.getProtectionAlgorithm().equals(senderMacCalculator.getAlgorithmIdentifier()));

        PBEMacCalculatorProvider macCalcProvider = new JcePBMac1CalculatorProviderBuilder().setProvider("BC").build();

        assertTrue(message.verify(macCalcProvider, senderMacPassword));

        assertEquals(PKIBody.TYPE_INIT_REQ, message.getBody().getType());

        CertificateReqMessages requestMessages = CertificateReqMessages.fromPKIBody(message.getBody());
        CertificateRequestMessage senderReqMessage = requestMessages.getRequests()[0];
        CertTemplate certTemplate = senderReqMessage.getCertTemplate();

        X509CertificateHolder cert = makeV3Certificate(certTemplate.getPublicKey(), certTemplate.getSubject(), dilKp, "CN=Dilithium Issuer");

        // Send response with encrypted certificate
        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        // note: use cert req ID as key ID, don't want to use issuer/serial in this case!

        edGen.addRecipientInfoGenerator(new JceKEMRecipientInfoGenerator(senderReqMessage.getCertReqId().getEncoded(),
            new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert).getPublicKey(), CMSAlgorithm.AES256_WRAP).setKDF(
            new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake256)));

        CMSEnvelopedData encryptedCert = edGen.generate(
            new CMSProcessableCMPCertificate(cert),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider("BC").build());

        CertificateResponseBuilder certRespBuilder = new CertificateResponseBuilder(senderReqMessage.getCertReqId(), new PKIStatusInfo(PKIStatus.granted));

        certRespBuilder.withCertificate(encryptedCert);

        CertificateRepMessageBuilder repMessageBuilder = new CertificateRepMessageBuilder(caCert);

        repMessageBuilder.addCertificateResponse(certRespBuilder.build());

        ContentSigner signer = new JcaContentSignerBuilder("Dilithium").setProvider("BCPQC").build(dilKp.getPrivate());

        CertificateRepMessage repMessage = repMessageBuilder.build();

        ProtectedPKIMessage responsePkixMessage = new ProtectedPKIMessageBuilder(sender, recipient)
            .setBody(PKIBody.TYPE_INIT_REP, repMessage)
            .build(signer);

        // decrypt the certificate

        assertTrue(responsePkixMessage.verify(new JcaContentVerifierProviderBuilder().build(caCert)));

        CertificateRepMessage certRepMessage = CertificateRepMessage.fromPKIBody(responsePkixMessage.getBody());

        CertificateResponse certResp = certRepMessage.getResponses()[0];

        assertEquals(true, certResp.hasEncryptedCertificate());

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

        RecipientInformationStore recipients = receivedEnvelope.getRecipientInfos();
//                System.err.println(ASN1Dump.dumpAsString(ASN1Primitive.fromByteArray(receivedEnvelope.getEncoded())));
        Collection c = recipients.getRecipients();

        assertEquals(1, c.size());

        RecipientInformation recInfo = (RecipientInformation)c.iterator().next();

        assertEquals(recInfo.getKeyEncryptionAlgOID(), BCObjectIdentifiers.kyber512.getId());

        // Note: we don't specify the provider here as we're actually using both BC and BCPQC

        byte[] recData = recInfo.getContent(new JceKEMEnvelopedRecipient(kybKp.getPrivate()));

        assertEquals(true, Arrays.equals(new CMPCertificate(cert.toASN1Structure()).getEncoded(), recData));

        // this is the preferred way of recovering an encrypted certificate

        CMPCertificate receivedCMPCert = certResp.getCertificate(new JceKEMEnvelopedRecipient(kybKp.getPrivate()));

        X509CertificateHolder receivedCert = new X509CertificateHolder(receivedCMPCert.getX509v3PKCert());

        X509CertificateHolder caCertHolder = certRepMessage.getX509Certificates()[0];

        assertEquals(true, receivedCert.isSignatureValid(new JcaContentVerifierProviderBuilder().build(caCertHolder)));

        // confirmation message calculation

        CertificateConfirmationContent content = new CertificateConfirmationContentBuilder()
            .addAcceptedCertificate(cert, BigInteger.ONE)
            .build(new JcaDigestCalculatorProviderBuilder().build());

        message = new ProtectedPKIMessageBuilder(sender, recipient)
            .setBody(PKIBody.TYPE_CERT_CONFIRM, content)
            .build(senderMacCalculator);

        assertTrue(content.getStatusMessages()[0].isVerified(receivedCert, new JcaDigestCalculatorProviderBuilder().build()));
        assertEquals(PKIBody.TYPE_CERT_CONFIRM, message.getBody().getType());

        // confirmation receiving

        CertificateConfirmationContent recContent = CertificateConfirmationContent.fromPKIBody(message.getBody());

        assertTrue(recContent.getStatusMessages()[0].isVerified(receivedCert, new JcaDigestCalculatorProviderBuilder().build()));
    }

    public void testNTRURequestWithDilithiumCA()
        throws Exception
    {
        char[] senderMacPassword = "secret".toCharArray();
        GeneralName sender = new GeneralName(new X500Name("CN=NTRU Subject"));
        GeneralName recipient = new GeneralName(new X500Name("CN=Dilithium Issuer"));

        KeyPairGenerator dilKpGen = KeyPairGenerator.getInstance("Dilithium", "BCPQC");

        dilKpGen.initialize(DilithiumParameterSpec.dilithium2);

        KeyPair dilKp = dilKpGen.generateKeyPair();

        X509CertificateHolder caCert = makeV3Certificate("CN=Dilithium Issuer", dilKp);

        KeyPairGenerator kybKpGen = KeyPairGenerator.getInstance("NTRU", "BCPQC");

        kybKpGen.initialize(NTRUParameterSpec.ntruhrss701);

        KeyPair ntruKp = kybKpGen.generateKeyPair();

        // initial request

        JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigIntegers.ONE);

        certReqBuild
            .setPublicKey(ntruKp.getPublic())
            .setSubject(X500Name.getInstance(sender.getName()))
            .setProofOfPossessionSubsequentMessage(SubsequentMessage.encrCert);

        CertificateReqMessagesBuilder certReqMsgsBldr = new CertificateReqMessagesBuilder();

        certReqMsgsBldr.addRequest(certReqBuild.build());

        MacCalculator senderMacCalculator = new JcePBMac1CalculatorBuilder("HmacSHA256", 256).setProvider("BC").build(senderMacPassword);

        ProtectedPKIMessage initMessage = new ProtectedPKIMessageBuilder(sender, recipient)
            .setBody(PKIBody.TYPE_INIT_REQ, certReqMsgsBldr.build())
            .build(senderMacCalculator);

        // extract

        assertTrue(initMessage.getProtectionAlgorithm().equals(senderMacCalculator.getAlgorithmIdentifier()));

        PBEMacCalculatorProvider macCalcProvider = new JcePBMac1CalculatorProviderBuilder().setProvider("BC").build();

        assertTrue(initMessage.verify(macCalcProvider, senderMacPassword));

        assertEquals(PKIBody.TYPE_INIT_REQ, initMessage.getBody().getType());

        CertificateReqMessages requestMessages = CertificateReqMessages.fromPKIBody(initMessage.getBody());
        CertificateRequestMessage senderReqMessage = requestMessages.getRequests()[0];
        CertTemplate certTemplate = senderReqMessage.getCertTemplate();

        X509CertificateHolder cert = makeV3Certificate(certTemplate.getPublicKey(), certTemplate.getSubject(), dilKp, "CN=Dilithium Issuer");

        // Send response with encrypted certificate
        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        // note: use cert req ID as key ID, don't want to use issuer/serial in this case!

        edGen.addRecipientInfoGenerator(new JceKEMRecipientInfoGenerator(senderReqMessage.getCertReqId().getEncoded(),
            new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert).getPublicKey(), CMSAlgorithm.AES256_WRAP)
            .setKDF(new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake256)));

        CMSEnvelopedData encryptedCert = edGen.generate(
            new CMSProcessableCMPCertificate(cert),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES192_CBC).setProvider("BC").build());

        CertificateResponseBuilder certRespBuilder = new CertificateResponseBuilder(senderReqMessage.getCertReqId(), new PKIStatusInfo(PKIStatus.granted));

        certRespBuilder.withCertificate(encryptedCert);

        CertificateRepMessageBuilder repMessageBuilder = new CertificateRepMessageBuilder(caCert);

        repMessageBuilder.addCertificateResponse(certRespBuilder.build());

        ContentSigner signer = new JcaContentSignerBuilder("Dilithium").setProvider("BCPQC").build(dilKp.getPrivate());

        CertificateRepMessage repMessage = repMessageBuilder.build();

        ProtectedPKIMessage responsePkixMessage = new ProtectedPKIMessageBuilder(sender, recipient)
            .setBody(PKIBody.TYPE_INIT_REP, repMessage)
            .build(signer);

        // decrypt the certificate

        assertTrue(responsePkixMessage.verify(new JcaContentVerifierProviderBuilder().build(caCert)));

        CertificateRepMessage certRepMessage = CertificateRepMessage.fromPKIBody(responsePkixMessage.getBody());

        CertificateResponse certResp = certRepMessage.getResponses()[0];

        assertEquals(true, certResp.hasEncryptedCertificate());

        // this is the long-way to decrypt, for testing
        CMSEnvelopedData receivedEnvelope = certResp.getEncryptedCertificate();
        RecipientInformationStore recipients = receivedEnvelope.getRecipientInfos();
        Collection c = recipients.getRecipients();

        assertEquals(1, c.size());

        RecipientInformation recInfo = (RecipientInformation)c.iterator().next();

        assertEquals(recInfo.getKeyEncryptionAlgOID(), BCObjectIdentifiers.ntruhrss701.getId());

        // Note: we don't specify the provider here as we're actually using both BC and BCPQC

        byte[] recData = recInfo.getContent(new JceKEMEnvelopedRecipient(ntruKp.getPrivate()));

        assertEquals(true, Arrays.equals(new CMPCertificate(cert.toASN1Structure()).getEncoded(), recData));

        // this is the preferred way of recovering an encrypted certificate

        CMPCertificate receivedCMPCert = certResp.getCertificate(new JceKEMEnvelopedRecipient(ntruKp.getPrivate()));

        X509CertificateHolder receivedCert = new X509CertificateHolder(receivedCMPCert.getX509v3PKCert());

        X509CertificateHolder caCertHolder = certRepMessage.getX509Certificates()[0];

        assertEquals(true, receivedCert.isSignatureValid(new JcaContentVerifierProviderBuilder().build(caCertHolder)));

        // confirmation message calculation

        CertificateConfirmationContent content = new CertificateConfirmationContentBuilder()
            .addAcceptedCertificate(cert, BigInteger.ONE)
            .build(new JcaDigestCalculatorProviderBuilder().build());

        ProtectedPKIMessage certConf = new ProtectedPKIMessageBuilder(sender, recipient)
            .setBody(PKIBody.TYPE_CERT_CONFIRM, content)
            .build(senderMacCalculator);

        assertTrue(content.getStatusMessages()[0].isVerified(receivedCert, new JcaDigestCalculatorProviderBuilder().build()));
        assertEquals(PKIBody.TYPE_CERT_CONFIRM, certConf.getBody().getType());

        // confirmation receiving

        CertificateConfirmationContent recContent = CertificateConfirmationContent.fromPKIBody(certConf.getBody());

        assertTrue(recContent.getStatusMessages()[0].isVerified(receivedCert, new JcaDigestCalculatorProviderBuilder().build()));

//        JcaPEMWriter pOut = new JcaPEMWriter(new FileWriter("/tmp/ntru_dil_cmp/ca_cert.pem"));
//        pOut.writeObject(caCert);
//        pOut.close();
//
//        pOut = new JcaPEMWriter(new FileWriter("/tmp/ntru_dil_cmp/ntru_priv.pem"));
//        pOut.writeObject(ntruKp.getPrivate());
//        pOut.close();
//
//        pOut = new JcaPEMWriter(new FileWriter("/tmp/ntru_dil_cmp/ntru_cert.pem"));
//        pOut.writeObject(cert);
//        pOut.close();
//
//        OutputStream fOut = new FileOutputStream("/tmp/ntru_dil_cmp/cmp_message.ir");
//        fOut.write(initMessage.toASN1Structure().getEncoded());
//        fOut.close();
//
//        fOut = new FileOutputStream("/tmp/ntru_dil_cmp/cmp_message.ip");
//        fOut.write(responsePkixMessage.toASN1Structure().getEncoded());
//        fOut.close();
//
//        fOut = new FileOutputStream("/tmp/ntru_dil_cmp/cmp_message.ip");
//        fOut.write(responsePkixMessage.toASN1Structure().getEncoded());
//        fOut.close();
//
//        fOut = new FileOutputStream("/tmp/ntru_dil_cmp/cmp_message.certConf");
//        fOut.write(certConf.toASN1Structure().getEncoded());
//        fOut.close();
//
//        System.err.println(ASN1Dump.dumpAsString(receivedEnvelope.toASN1Structure()));
    }

    public void testBIKERequestWithDilithiumCA()
        throws Exception
    {
        char[] senderMacPassword = "secret".toCharArray();
        GeneralName sender = new GeneralName(new X500Name("CN=Bike128 Subject"));
        GeneralName recipient = new GeneralName(new X500Name("CN=Dilithium Issuer"));

        KeyPairGenerator dilKpGen = KeyPairGenerator.getInstance("Dilithium", "BCPQC");

        dilKpGen.initialize(DilithiumParameterSpec.dilithium2);

        KeyPair dilKp = dilKpGen.generateKeyPair();

        X509CertificateHolder caCert = makeV3Certificate("CN=Dilithium Issuer", dilKp);

        KeyPairGenerator kybKpGen = KeyPairGenerator.getInstance("BIKE", "BCPQC");

        kybKpGen.initialize(BIKEParameterSpec.bike128);

        KeyPair ntruKp = kybKpGen.generateKeyPair();

        // initial request

        JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigIntegers.ONE);

        certReqBuild
            .setPublicKey(ntruKp.getPublic())
            .setSubject(X500Name.getInstance(sender.getName()))
            .setProofOfPossessionSubsequentMessage(SubsequentMessage.encrCert);

        CertificateReqMessagesBuilder certReqMsgsBldr = new CertificateReqMessagesBuilder();

        certReqMsgsBldr.addRequest(certReqBuild.build());

        MacCalculator senderMacCalculator = new JcePBMac1CalculatorBuilder("HmacSHA256", 256).setProvider("BC").build(senderMacPassword);

        ProtectedPKIMessage initMessage = new ProtectedPKIMessageBuilder(sender, recipient)
            .setBody(PKIBody.TYPE_INIT_REQ, certReqMsgsBldr.build())
            .build(senderMacCalculator);

        // extract

        assertTrue(initMessage.getProtectionAlgorithm().equals(senderMacCalculator.getAlgorithmIdentifier()));

        PBEMacCalculatorProvider macCalcProvider = new JcePBMac1CalculatorProviderBuilder().setProvider("BC").build();

        assertTrue(initMessage.verify(macCalcProvider, senderMacPassword));

        assertEquals(PKIBody.TYPE_INIT_REQ, initMessage.getBody().getType());

        CertificateReqMessages requestMessages = CertificateReqMessages.fromPKIBody(initMessage.getBody());
        CertificateRequestMessage senderReqMessage = requestMessages.getRequests()[0];
        CertTemplate certTemplate = senderReqMessage.getCertTemplate();

        X509CertificateHolder cert = makeV3Certificate(certTemplate.getPublicKey(), certTemplate.getSubject(), dilKp, "CN=Dilithium Issuer");

        // Send response with encrypted certificate
        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        // note: use cert req ID as key ID, don't want to use issuer/serial in this case!

        edGen.addRecipientInfoGenerator(new JceKEMRecipientInfoGenerator(senderReqMessage.getCertReqId().getEncoded(),
            new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert).getPublicKey(), CMSAlgorithm.AES256_WRAP)
            .setKDF(new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake256)));

        CMSEnvelopedData encryptedCert = edGen.generate(
            new CMSProcessableCMPCertificate(cert),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES192_CBC).setProvider("BC").build());

        CertificateResponseBuilder certRespBuilder = new CertificateResponseBuilder(senderReqMessage.getCertReqId(), new PKIStatusInfo(PKIStatus.granted));

        certRespBuilder.withCertificate(encryptedCert);

        CertificateRepMessageBuilder repMessageBuilder = new CertificateRepMessageBuilder(caCert);

        repMessageBuilder.addCertificateResponse(certRespBuilder.build());

        ContentSigner signer = new JcaContentSignerBuilder("Dilithium").setProvider("BCPQC").build(dilKp.getPrivate());

        CertificateRepMessage repMessage = repMessageBuilder.build();

        ProtectedPKIMessage responsePkixMessage = new ProtectedPKIMessageBuilder(sender, recipient)
            .setBody(PKIBody.TYPE_INIT_REP, repMessage)
            .build(signer);

        // decrypt the certificate

        assertTrue(responsePkixMessage.verify(new JcaContentVerifierProviderBuilder().build(caCert)));

        CertificateRepMessage certRepMessage = CertificateRepMessage.fromPKIBody(responsePkixMessage.getBody());

        CertificateResponse certResp = certRepMessage.getResponses()[0];

        assertEquals(true, certResp.hasEncryptedCertificate());

        // this is the long-way to decrypt, for testing
        CMSEnvelopedData receivedEnvelope = certResp.getEncryptedCertificate();
        RecipientInformationStore recipients = receivedEnvelope.getRecipientInfos();
        Collection c = recipients.getRecipients();

        assertEquals(1, c.size());

        RecipientInformation recInfo = (RecipientInformation)c.iterator().next();

        assertEquals(recInfo.getKeyEncryptionAlgOID(), BCObjectIdentifiers.bike128.getId());

        // Note: we don't specify the provider here as we're actually using both BC and BCPQC

        byte[] recData = recInfo.getContent(new JceKEMEnvelopedRecipient(ntruKp.getPrivate()));

        assertEquals(true, Arrays.equals(new CMPCertificate(cert.toASN1Structure()).getEncoded(), recData));

        // this is the preferred way of recovering an encrypted certificate

        CMPCertificate receivedCMPCert = certResp.getCertificate(new JceKEMEnvelopedRecipient(ntruKp.getPrivate()));

        X509CertificateHolder receivedCert = new X509CertificateHolder(receivedCMPCert.getX509v3PKCert());

        X509CertificateHolder caCertHolder = certRepMessage.getX509Certificates()[0];

        assertEquals(true, receivedCert.isSignatureValid(new JcaContentVerifierProviderBuilder().build(caCertHolder)));

        // confirmation message calculation

        CertificateConfirmationContent content = new CertificateConfirmationContentBuilder()
            .addAcceptedCertificate(cert, BigInteger.ONE)
            .build(new JcaDigestCalculatorProviderBuilder().build());

        ProtectedPKIMessage certConf = new ProtectedPKIMessageBuilder(sender, recipient)
            .setBody(PKIBody.TYPE_CERT_CONFIRM, content)
            .build(senderMacCalculator);

        assertTrue(content.getStatusMessages()[0].isVerified(receivedCert, new JcaDigestCalculatorProviderBuilder().build()));
        assertEquals(PKIBody.TYPE_CERT_CONFIRM, certConf.getBody().getType());

        // confirmation receiving

        CertificateConfirmationContent recContent = CertificateConfirmationContent.fromPKIBody(certConf.getBody());

        assertTrue(recContent.getStatusMessages()[0].isVerified(receivedCert, new JcaDigestCalculatorProviderBuilder().build()));

//        JcaPEMWriter pOut = new JcaPEMWriter(new FileWriter("/tmp/bike_dil_cmp/ca_cert.pem"));
//        pOut.writeObject(caCert);
//        pOut.close();
//
//        pOut = new JcaPEMWriter(new FileWriter("/tmp/bike_dil_cmp/bike_priv.pem"));
//        pOut.writeObject(ntruKp.getPrivate());
//        pOut.close();
//
//        pOut = new JcaPEMWriter(new FileWriter("/tmp/bike_dil_cmp/bike_cert.pem"));
//        pOut.writeObject(cert);
//        pOut.close();
//
//        OutputStream fOut = new FileOutputStream("/tmp/bike_dil_cmp/cmp_message.ir");
//        fOut.write(initMessage.toASN1Structure().getEncoded());
//        fOut.close();
//
//        fOut = new FileOutputStream("/tmp/bike_dil_cmp/cmp_message.ip");
//        fOut.write(responsePkixMessage.toASN1Structure().getEncoded());
//        fOut.close();
//
//        fOut = new FileOutputStream("/tmp/bike_dil_cmp/cmp_message.ip");
//        fOut.write(responsePkixMessage.toASN1Structure().getEncoded());
//        fOut.close();
//
//        fOut = new FileOutputStream("/tmp/bike_dil_cmp/cmp_message.certConf");
//        fOut.write(certConf.toASN1Structure().getEncoded());
//        fOut.close();
//
//        System.err.println(ASN1Dump.dumpAsString(receivedEnvelope.toASN1Structure()));
    }

    public void testHQCRequestWithDilithiumCA()
        throws Exception
    {
        char[] senderMacPassword = "secret".toCharArray();
        GeneralName sender = new GeneralName(new X500Name("CN=HQC128 Subject"));
        GeneralName recipient = new GeneralName(new X500Name("CN=Dilithium Issuer"));

        KeyPairGenerator dilKpGen = KeyPairGenerator.getInstance("Dilithium", "BCPQC");

        dilKpGen.initialize(DilithiumParameterSpec.dilithium2);

        KeyPair dilKp = dilKpGen.generateKeyPair();

        X509CertificateHolder caCert = makeV3Certificate("CN=Dilithium Issuer", dilKp);

        KeyPairGenerator kybKpGen = KeyPairGenerator.getInstance("HQC", "BCPQC");

        kybKpGen.initialize(HQCParameterSpec.hqc128);

        KeyPair hqcKp = kybKpGen.generateKeyPair();

        // initial request

        JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigIntegers.ONE);

        certReqBuild
            .setPublicKey(hqcKp.getPublic())
            .setSubject(X500Name.getInstance(sender.getName()))
            .setProofOfPossessionSubsequentMessage(SubsequentMessage.encrCert);

        CertificateReqMessagesBuilder certReqMsgsBldr = new CertificateReqMessagesBuilder();

        certReqMsgsBldr.addRequest(certReqBuild.build());

        MacCalculator senderMacCalculator = new JcePBMac1CalculatorBuilder("HmacSHA256", 256).setProvider("BC").build(senderMacPassword);

        ProtectedPKIMessage initMessage = new ProtectedPKIMessageBuilder(sender, recipient)
            .setBody(PKIBody.TYPE_INIT_REQ, certReqMsgsBldr.build())
            .build(senderMacCalculator);

        // extract

        assertTrue(initMessage.getProtectionAlgorithm().equals(senderMacCalculator.getAlgorithmIdentifier()));

        PBEMacCalculatorProvider macCalcProvider = new JcePBMac1CalculatorProviderBuilder().setProvider("BC").build();

        assertTrue(initMessage.verify(macCalcProvider, senderMacPassword));

        assertEquals(PKIBody.TYPE_INIT_REQ, initMessage.getBody().getType());

        CertificateReqMessages requestMessages = CertificateReqMessages.fromPKIBody(initMessage.getBody());
        CertificateRequestMessage senderReqMessage = requestMessages.getRequests()[0];
        CertTemplate certTemplate = senderReqMessage.getCertTemplate();

        X509CertificateHolder cert = makeV3Certificate(certTemplate.getPublicKey(), certTemplate.getSubject(), dilKp, "CN=Dilithium Issuer");

        // Send response with encrypted certificate
        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        // note: use cert req ID as key ID, don't want to use issuer/serial in this case!

        edGen.addRecipientInfoGenerator(new JceKEMRecipientInfoGenerator(senderReqMessage.getCertReqId().getEncoded(),
            new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert).getPublicKey(), CMSAlgorithm.AES256_WRAP)
            .setKDF(new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake256)));

        CMSEnvelopedData encryptedCert = edGen.generate(
            new CMSProcessableCMPCertificate(cert),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES192_CBC).setProvider("BC").build());

        CertificateResponseBuilder certRespBuilder = new CertificateResponseBuilder(senderReqMessage.getCertReqId(), new PKIStatusInfo(PKIStatus.granted));

        certRespBuilder.withCertificate(encryptedCert);

        CertificateRepMessageBuilder repMessageBuilder = new CertificateRepMessageBuilder(caCert);

        repMessageBuilder.addCertificateResponse(certRespBuilder.build());

        ContentSigner signer = new JcaContentSignerBuilder("Dilithium").setProvider("BCPQC").build(dilKp.getPrivate());

        CertificateRepMessage repMessage = repMessageBuilder.build();

        ProtectedPKIMessage responsePkixMessage = new ProtectedPKIMessageBuilder(sender, recipient)
            .setBody(PKIBody.TYPE_INIT_REP, repMessage)
            .build(signer);

        // decrypt the certificate

        assertTrue(responsePkixMessage.verify(new JcaContentVerifierProviderBuilder().build(caCert)));

        CertificateRepMessage certRepMessage = CertificateRepMessage.fromPKIBody(responsePkixMessage.getBody());

        CertificateResponse certResp = certRepMessage.getResponses()[0];

        assertEquals(true, certResp.hasEncryptedCertificate());

        // this is the long-way to decrypt, for testing
        CMSEnvelopedData receivedEnvelope = certResp.getEncryptedCertificate();
        RecipientInformationStore recipients = receivedEnvelope.getRecipientInfos();
        Collection c = recipients.getRecipients();

        assertEquals(1, c.size());

        RecipientInformation recInfo = (RecipientInformation)c.iterator().next();

        assertEquals(recInfo.getKeyEncryptionAlgOID(), BCObjectIdentifiers.hqc128.getId());

        // Note: we don't specify the provider here as we're actually using both BC and BCPQC

        byte[] recData = recInfo.getContent(new JceKEMEnvelopedRecipient(hqcKp.getPrivate()));

        assertEquals(true, Arrays.equals(new CMPCertificate(cert.toASN1Structure()).getEncoded(), recData));

        // this is the preferred way of recovering an encrypted certificate

        CMPCertificate receivedCMPCert = certResp.getCertificate(new JceKEMEnvelopedRecipient(hqcKp.getPrivate()));

        X509CertificateHolder receivedCert = new X509CertificateHolder(receivedCMPCert.getX509v3PKCert());

        X509CertificateHolder caCertHolder = certRepMessage.getX509Certificates()[0];

        assertEquals(true, receivedCert.isSignatureValid(new JcaContentVerifierProviderBuilder().build(caCertHolder)));

        // confirmation message calculation

        CertificateConfirmationContent content = new CertificateConfirmationContentBuilder()
            .addAcceptedCertificate(cert, BigInteger.ONE)
            .build(new JcaDigestCalculatorProviderBuilder().build());

        ProtectedPKIMessage certConf = new ProtectedPKIMessageBuilder(sender, recipient)
            .setBody(PKIBody.TYPE_CERT_CONFIRM, content)
            .build(senderMacCalculator);

        assertTrue(content.getStatusMessages()[0].isVerified(receivedCert, new JcaDigestCalculatorProviderBuilder().build()));
        assertEquals(PKIBody.TYPE_CERT_CONFIRM, certConf.getBody().getType());

        // confirmation receiving

        CertificateConfirmationContent recContent = CertificateConfirmationContent.fromPKIBody(certConf.getBody());

        assertTrue(recContent.getStatusMessages()[0].isVerified(receivedCert, new JcaDigestCalculatorProviderBuilder().build()));

//        JcaPEMWriter pOut = new JcaPEMWriter(new FileWriter("/tmp/hqc_dil_cmp/ca_cert.pem"));
//        pOut.writeObject(caCert);
//        pOut.close();
//
//        pOut = new JcaPEMWriter(new FileWriter("/tmp/hqc_dil_cmp/hqc_priv.pem"));
//        pOut.writeObject(hqcKp.getPrivate());
//        pOut.close();
//
//        pOut = new JcaPEMWriter(new FileWriter("/tmp/hqc_dil_cmp/hqc_cert.pem"));
//        pOut.writeObject(cert);
//        pOut.close();
//
//        OutputStream fOut = new FileOutputStream("/tmp/hqc_dil_cmp/cmp_message.ir");
//        fOut.write(initMessage.toASN1Structure().getEncoded());
//        fOut.close();
//
//        fOut = new FileOutputStream("/tmp/hqc_dil_cmp/cmp_message.ip");
//        fOut.write(responsePkixMessage.toASN1Structure().getEncoded());
//        fOut.close();
//
//        fOut = new FileOutputStream("/tmp/hqc_dil_cmp/cmp_message.ip");
//        fOut.write(responsePkixMessage.toASN1Structure().getEncoded());
//        fOut.close();
//
//        fOut = new FileOutputStream("/tmp/hqc_dil_cmp/cmp_message.certConf");
//        fOut.write(certConf.toASN1Structure().getEncoded());
//        fOut.close();
//
//        System.err.println(ASN1Dump.dumpAsString(receivedEnvelope.toASN1Structure()));
    }

    public void testCMCERequestWithDilithiumCA()
        throws Exception
    {
        char[] senderMacPassword = "secret".toCharArray();
        GeneralName sender = new GeneralName(new X500Name("CN=mceliece3488864 Subject"));
        GeneralName recipient = new GeneralName(new X500Name("CN=Dilithium Issuer"));

        KeyPairGenerator dilKpGen = KeyPairGenerator.getInstance("Dilithium", "BCPQC");

        dilKpGen.initialize(DilithiumParameterSpec.dilithium2);

        KeyPair dilKp = dilKpGen.generateKeyPair();

        X509CertificateHolder caCert = makeV3Certificate("CN=Dilithium Issuer", dilKp);

        KeyPairGenerator cmceKpGen = KeyPairGenerator.getInstance("CMCE", "BCPQC");

        cmceKpGen.initialize(CMCEParameterSpec.mceliece348864);

        KeyPair hqcKp = cmceKpGen.generateKeyPair();

        // initial request

        JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigIntegers.ONE);

        certReqBuild
            .setPublicKey(hqcKp.getPublic())
            .setSubject(X500Name.getInstance(sender.getName()))
            .setProofOfPossessionSubsequentMessage(SubsequentMessage.encrCert);

        CertificateReqMessagesBuilder certReqMsgsBldr = new CertificateReqMessagesBuilder();

        certReqMsgsBldr.addRequest(certReqBuild.build());

        MacCalculator senderMacCalculator = new JcePBMac1CalculatorBuilder("HmacSHA256", 256).setProvider("BC").build(senderMacPassword);

        ProtectedPKIMessage initMessage = new ProtectedPKIMessageBuilder(sender, recipient)
            .setBody(PKIBody.TYPE_INIT_REQ, certReqMsgsBldr.build())
            .build(senderMacCalculator);

        // extract

        assertTrue(initMessage.getProtectionAlgorithm().equals(senderMacCalculator.getAlgorithmIdentifier()));

        PBEMacCalculatorProvider macCalcProvider = new JcePBMac1CalculatorProviderBuilder().setProvider("BC").build();

        assertTrue(initMessage.verify(macCalcProvider, senderMacPassword));

        assertEquals(PKIBody.TYPE_INIT_REQ, initMessage.getBody().getType());

        CertificateReqMessages requestMessages = CertificateReqMessages.fromPKIBody(initMessage.getBody());
        CertificateRequestMessage senderReqMessage = requestMessages.getRequests()[0];
        CertTemplate certTemplate = senderReqMessage.getCertTemplate();

        X509CertificateHolder cert = makeV3Certificate(certTemplate.getPublicKey(), certTemplate.getSubject(), dilKp, "CN=Dilithium Issuer");

        // Send response with encrypted certificate
        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        // note: use cert req ID as key ID, don't want to use issuer/serial in this case!

        edGen.addRecipientInfoGenerator(new JceKEMRecipientInfoGenerator(senderReqMessage.getCertReqId().getEncoded(),
            new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert).getPublicKey(), CMSAlgorithm.AES256_WRAP)
            .setKDF(new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake256)));

        CMSEnvelopedData encryptedCert = edGen.generate(
            new CMSProcessableCMPCertificate(cert),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES192_CBC).setProvider("BC").build());

        CertificateResponseBuilder certRespBuilder = new CertificateResponseBuilder(senderReqMessage.getCertReqId(), new PKIStatusInfo(PKIStatus.granted));

        certRespBuilder.withCertificate(encryptedCert);

        CertificateRepMessageBuilder repMessageBuilder = new CertificateRepMessageBuilder(caCert);

        repMessageBuilder.addCertificateResponse(certRespBuilder.build());

        ContentSigner signer = new JcaContentSignerBuilder("Dilithium").setProvider("BCPQC").build(dilKp.getPrivate());

        CertificateRepMessage repMessage = repMessageBuilder.build();

        ProtectedPKIMessage responsePkixMessage = new ProtectedPKIMessageBuilder(sender, recipient)
            .setBody(PKIBody.TYPE_INIT_REP, repMessage)
            .build(signer);

        // decrypt the certificate

        assertTrue(responsePkixMessage.verify(new JcaContentVerifierProviderBuilder().build(caCert)));

        CertificateRepMessage certRepMessage = CertificateRepMessage.fromPKIBody(responsePkixMessage.getBody());

        CertificateResponse certResp = certRepMessage.getResponses()[0];

        assertEquals(true, certResp.hasEncryptedCertificate());

        // this is the long-way to decrypt, for testing
        CMSEnvelopedData receivedEnvelope = certResp.getEncryptedCertificate();
        RecipientInformationStore recipients = receivedEnvelope.getRecipientInfos();
        Collection c = recipients.getRecipients();

        assertEquals(1, c.size());

        RecipientInformation recInfo = (RecipientInformation)c.iterator().next();

        assertEquals(recInfo.getKeyEncryptionAlgOID(), BCObjectIdentifiers.mceliece348864_r3.getId());

        // Note: we don't specify the provider here as we're actually using both BC and BCPQC

        byte[] recData = recInfo.getContent(new JceKEMEnvelopedRecipient(hqcKp.getPrivate()));

        assertEquals(true, Arrays.equals(new CMPCertificate(cert.toASN1Structure()).getEncoded(), recData));

        // this is the preferred way of recovering an encrypted certificate

        CMPCertificate receivedCMPCert = certResp.getCertificate(new JceKEMEnvelopedRecipient(hqcKp.getPrivate()));

        X509CertificateHolder receivedCert = new X509CertificateHolder(receivedCMPCert.getX509v3PKCert());

        X509CertificateHolder caCertHolder = certRepMessage.getX509Certificates()[0];

        assertEquals(true, receivedCert.isSignatureValid(new JcaContentVerifierProviderBuilder().build(caCertHolder)));

        // confirmation message calculation

        CertificateConfirmationContent content = new CertificateConfirmationContentBuilder()
            .addAcceptedCertificate(cert, BigInteger.ONE)
            .build(new JcaDigestCalculatorProviderBuilder().build());

        ProtectedPKIMessage certConf = new ProtectedPKIMessageBuilder(sender, recipient)
            .setBody(PKIBody.TYPE_CERT_CONFIRM, content)
            .build(senderMacCalculator);

        assertTrue(content.getStatusMessages()[0].isVerified(receivedCert, new JcaDigestCalculatorProviderBuilder().build()));
        assertEquals(PKIBody.TYPE_CERT_CONFIRM, certConf.getBody().getType());

        // confirmation receiving

        CertificateConfirmationContent recContent = CertificateConfirmationContent.fromPKIBody(certConf.getBody());

        assertTrue(recContent.getStatusMessages()[0].isVerified(receivedCert, new JcaDigestCalculatorProviderBuilder().build()));

//        JcaPEMWriter pOut = new JcaPEMWriter(new FileWriter("/tmp/cmce_dil_cmp/ca_cert.pem"));
//        pOut.writeObject(caCert);
//        pOut.close();
//
//        pOut = new JcaPEMWriter(new FileWriter("/tmp/cmce_dil_cmp/cmce_priv.pem"));
//        pOut.writeObject(hqcKp.getPrivate());
//        pOut.close();
//
//        pOut = new JcaPEMWriter(new FileWriter("/tmp/cmce_dil_cmp/cmce_cert.pem"));
//        pOut.writeObject(cert);
//        pOut.close();
//
//        OutputStream fOut = new FileOutputStream("/tmp/cmce_dil_cmp/cmp_message.ir");
//        fOut.write(initMessage.toASN1Structure().getEncoded());
//        fOut.close();
//
//        fOut = new FileOutputStream("/tmp/cmce_dil_cmp/cmp_message.ip");
//        fOut.write(responsePkixMessage.toASN1Structure().getEncoded());
//        fOut.close();
//
//        fOut = new FileOutputStream("/tmp/cmce_dil_cmp/cmp_message.ip");
//        fOut.write(responsePkixMessage.toASN1Structure().getEncoded());
//        fOut.close();
//
//        fOut = new FileOutputStream("/tmp/cmce_dil_cmp/cmp_message.certConf");
//        fOut.write(certConf.toASN1Structure().getEncoded());
//        fOut.close();
//
//        System.err.println(ASN1Dump.dumpAsString(receivedEnvelope.toASN1Structure()));
    }

    public void testExternalCMCERequestWithDilithiumCA()
            throws Exception
        {
            char[] senderMacPassword = "secret".toCharArray();
            GeneralName sender = new GeneralName(new X500Name("CN=mceliece3488864 Subject"));
            GeneralName recipient = new GeneralName(new X500Name("CN=Dilithium Issuer"));

            KeyPairGenerator dilKpGen = KeyPairGenerator.getInstance("Dilithium", "BCPQC");

            dilKpGen.initialize(DilithiumParameterSpec.dilithium2);

            KeyPair dilKp = dilKpGen.generateKeyPair();

            X509CertificateHolder caCert = makeV3Certificate("CN=Dilithium Issuer", dilKp);

            KeyPairGenerator cmceKpGen = KeyPairGenerator.getInstance("CMCE", "BCPQC");

            cmceKpGen.initialize(CMCEParameterSpec.mceliece348864);

            KeyPair hqcKp = cmceKpGen.generateKeyPair();

            // initial request

            JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigIntegers.ONE);

            certReqBuild
                .setPublicKey(hqcKp.getPublic())
                .setSubject(X500Name.getInstance(sender.getName()))
                .setProofOfPossessionSubsequentMessage(SubsequentMessage.encrCert);

            CertificateReqMessagesBuilder certReqMsgsBldr = new CertificateReqMessagesBuilder();

            certReqMsgsBldr.addRequest(certReqBuild.build());

            MacCalculator senderMacCalculator = new JcePBMac1CalculatorBuilder("HmacSHA256", 256).setProvider("BC").build(senderMacPassword);

            ProtectedPKIMessage initMessage = new ProtectedPKIMessageBuilder(sender, recipient)
                .setBody(PKIBody.TYPE_INIT_REQ, certReqMsgsBldr.build())
                .build(senderMacCalculator);

            // extract

            assertTrue(initMessage.getProtectionAlgorithm().equals(senderMacCalculator.getAlgorithmIdentifier()));

            PBEMacCalculatorProvider macCalcProvider = new JcePBMac1CalculatorProviderBuilder().setProvider("BC").build();

            assertTrue(initMessage.verify(macCalcProvider, senderMacPassword));

            assertEquals(PKIBody.TYPE_INIT_REQ, initMessage.getBody().getType());

            CertificateReqMessages requestMessages = CertificateReqMessages.fromPKIBody(initMessage.getBody());
            CertificateRequestMessage senderReqMessage = requestMessages.getRequests()[0];
            CertTemplate certTemplate = senderReqMessage.getCertTemplate();

            X509CertificateHolder cert = makeV3Certificate(certTemplate.getPublicKey(), certTemplate.getSubject(), dilKp, "CN=Dilithium Issuer");

            // Send response with encrypted certificate
            CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

            // note: use cert req ID as key ID, don't want to use issuer/serial in this case!

            edGen.addRecipientInfoGenerator(new JceKEMRecipientInfoGenerator(senderReqMessage.getCertReqId().getEncoded(),
                new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert).getPublicKey(), CMSAlgorithm.AES256_WRAP)
                .setKDF(new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake256)));

            CMSEnvelopedData encryptedCert = edGen.generate(
                new CMSProcessableCMPCertificate(cert),
                new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES192_CBC).setProvider("BC").build());

            CertificateResponseBuilder certRespBuilder = new CertificateResponseBuilder(senderReqMessage.getCertReqId(), new PKIStatusInfo(PKIStatus.granted));

            certRespBuilder.withCertificate(encryptedCert);

            CertificateRepMessageBuilder repMessageBuilder = new CertificateRepMessageBuilder(caCert);

            repMessageBuilder.addCertificateResponse(certRespBuilder.build());

            ContentSigner signer = new JcaContentSignerBuilder("Dilithium").setProvider("BCPQC").build(dilKp.getPrivate());

            CertificateRepMessage repMessage = repMessageBuilder.build();

            ProtectedPKIMessage responsePkixMessage = new ProtectedPKIMessageBuilder(sender, recipient)
                .setBody(PKIBody.TYPE_INIT_REP, repMessage)
                .build(signer);

            // decrypt the certificate

            assertTrue(responsePkixMessage.verify(new JcaContentVerifierProviderBuilder().build(caCert)));

            CertificateRepMessage certRepMessage = CertificateRepMessage.fromPKIBody(responsePkixMessage.getBody());

            CertificateResponse certResp = certRepMessage.getResponses()[0];

            assertEquals(true, certResp.hasEncryptedCertificate());

            // this is the long-way to decrypt, for testing
            CMSEnvelopedData receivedEnvelope = certResp.getEncryptedCertificate();
            RecipientInformationStore recipients = receivedEnvelope.getRecipientInfos();
            Collection c = recipients.getRecipients();

            assertEquals(1, c.size());

            RecipientInformation recInfo = (RecipientInformation)c.iterator().next();

            assertEquals(recInfo.getKeyEncryptionAlgOID(), BCObjectIdentifiers.mceliece348864_r3.getId());

            // Note: we don't specify the provider here as we're actually using both BC and BCPQC

            byte[] recData = recInfo.getContent(new JceKEMEnvelopedRecipient(hqcKp.getPrivate()));

            assertEquals(true, Arrays.equals(new CMPCertificate(cert.toASN1Structure()).getEncoded(), recData));

            // this is the preferred way of recovering an encrypted certificate

            CMPCertificate receivedCMPCert = certResp.getCertificate(new JceKEMEnvelopedRecipient(hqcKp.getPrivate()));

            X509CertificateHolder receivedCert = new X509CertificateHolder(receivedCMPCert.getX509v3PKCert());

            X509CertificateHolder caCertHolder = certRepMessage.getX509Certificates()[0];

            assertEquals(true, receivedCert.isSignatureValid(new JcaContentVerifierProviderBuilder().build(caCertHolder)));

            // confirmation message calculation

            CertificateConfirmationContent content = new CertificateConfirmationContentBuilder()
                .addAcceptedCertificate(cert, BigInteger.ONE)
                .build(new JcaDigestCalculatorProviderBuilder().build());

            ProtectedPKIMessage certConf = new ProtectedPKIMessageBuilder(sender, recipient)
                .setBody(PKIBody.TYPE_CERT_CONFIRM, content)
                .build(senderMacCalculator);

            assertTrue(content.getStatusMessages()[0].isVerified(receivedCert, new JcaDigestCalculatorProviderBuilder().build()));
            assertEquals(PKIBody.TYPE_CERT_CONFIRM, certConf.getBody().getType());

            // confirmation receiving

            CertificateConfirmationContent recContent = CertificateConfirmationContent.fromPKIBody(certConf.getBody());

            assertTrue(recContent.getStatusMessages()[0].isVerified(receivedCert, new JcaDigestCalculatorProviderBuilder().build()));

    //        JcaPEMWriter pOut = new JcaPEMWriter(new FileWriter("/tmp/cmce_dil_cmp/ca_cert.pem"));
    //        pOut.writeObject(caCert);
    //        pOut.close();
    //
    //        pOut = new JcaPEMWriter(new FileWriter("/tmp/cmce_dil_cmp/cmce_priv.pem"));
    //        pOut.writeObject(hqcKp.getPrivate());
    //        pOut.close();
    //
    //        pOut = new JcaPEMWriter(new FileWriter("/tmp/cmce_dil_cmp/cmce_cert.pem"));
    //        pOut.writeObject(cert);
    //        pOut.close();
    //
    //        OutputStream fOut = new FileOutputStream("/tmp/cmce_dil_cmp/cmp_message.ir");
    //        fOut.write(initMessage.toASN1Structure().getEncoded());
    //        fOut.close();
    //
    //        fOut = new FileOutputStream("/tmp/cmce_dil_cmp/cmp_message.ip");
    //        fOut.write(responsePkixMessage.toASN1Structure().getEncoded());
    //        fOut.close();
    //
    //        fOut = new FileOutputStream("/tmp/cmce_dil_cmp/cmp_message.ip");
    //        fOut.write(responsePkixMessage.toASN1Structure().getEncoded());
    //        fOut.close();
    //
    //        fOut = new FileOutputStream("/tmp/cmce_dil_cmp/cmp_message.certConf");
    //        fOut.write(certConf.toASN1Structure().getEncoded());
    //        fOut.close();
    //
    //        System.err.println(ASN1Dump.dumpAsString(receivedEnvelope.toASN1Structure()));
        }

    private static X509CertificateHolder makeV3Certificate(String _subDN, KeyPair issKP)
        throws OperatorCreationException, CertException, CertIOException
    {
        PrivateKey issPriv = issKP.getPrivate();
        PublicKey issPub = issKP.getPublic();

        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
            new X500Name(_subDN),
            BigInteger.valueOf(System.currentTimeMillis()),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
            new X500Name(_subDN),
            issKP.getPublic());

        certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));

        ContentSigner signer = new JcaContentSignerBuilder("Dilithium").build(issPriv);

        X509CertificateHolder certHolder = certGen.build(signer);

        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder().build(issPub);

        assertTrue(certHolder.isSignatureValid(verifier));

        return certHolder;
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
}
