package org.bouncycastle.cert.cmp.test;

import java.io.FileWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encoding;
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
import org.bouncycastle.cert.cmp.ChallengeContent;
import org.bouncycastle.cert.cmp.POPODecryptionKeyChallengeContent;
import org.bouncycastle.cert.cmp.POPODecryptionKeyChallengeContentBuilder;
import org.bouncycastle.cert.cmp.POPODecryptionKeyResponseContent;
import org.bouncycastle.cert.cmp.POPODecryptionKeyResponseContentBuilder;
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
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
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
import org.bouncycastle.pqc.jcajce.spec.HQCParameterSpec;
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

    public void testMlKemRequestWithMlDsaCA()
        throws Exception
    {
        char[] senderMacPassword = "secret".toCharArray();
        GeneralName sender = new GeneralName(new X500Name("CN=ML-KEM Subject"));
        GeneralName recipient = new GeneralName(new X500Name("CN=ML-DSA Issuer"));

        KeyPairGenerator dilKpGen = KeyPairGenerator.getInstance("ML-DSA", "BC");

        dilKpGen.initialize(MLDSAParameterSpec.ml_dsa_65);

        KeyPair dilKp = dilKpGen.generateKeyPair();

        X509CertificateHolder caCert = makeV3Certificate("CN=ML-DSA Issuer", dilKp);

        KeyPairGenerator kybKpGen = KeyPairGenerator.getInstance("ML-KEM", "BC");

        kybKpGen.initialize(MLKEMParameterSpec.ml_kem_768);

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

        X509CertificateHolder cert = makeV3Certificate(certTemplate.getPublicKey(), certTemplate.getSubject(), dilKp, "CN=ML-DSA Issuer");

        // Send response with encrypted certificate
        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        // note: use cert req ID as key ID, don't want to use issuer/serial in this case!

        edGen.addRecipientInfoGenerator(new JceKEMRecipientInfoGenerator(senderReqMessage.getCertReqId().getEncoded(),
            new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert).getPublicKey(), CMSAlgorithm.AES256_WRAP).setKDF(
            new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake256)));

        CMSEnvelopedData encryptedCert = edGen.generate(
            new CMSProcessableCMPCertificate(cert),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider("BC").build());

//        System.err.println(ASN1Dump.dumpAsString(encryptedCert.toASN1Structure()));
        CertificateResponseBuilder certRespBuilder = new CertificateResponseBuilder(senderReqMessage.getCertReqId(), new PKIStatusInfo(PKIStatus.granted));

        certRespBuilder.withCertificate(encryptedCert);

        CertificateRepMessageBuilder repMessageBuilder = new CertificateRepMessageBuilder(caCert);

        repMessageBuilder.addCertificateResponse(certRespBuilder.build());

        ContentSigner signer = new JcaContentSignerBuilder("ML-DSA").setProvider("BC").build(dilKp.getPrivate());

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
        CMSEnvelopedData receivedEnvelope = new CMSEnvelopedData(certResp.getEncryptedCertificate().toASN1Structure().getEncoded(ASN1Encoding.DL));

        JcaPEMWriter pOut = new JcaPEMWriter(new FileWriter("/tmp/mlkem_cms/mlkem_cert_enveloped.pem"));
        pOut.writeObject(receivedEnvelope.toASN1Structure());
        pOut.close();

        pOut = new JcaPEMWriter(new FileWriter("/tmp/mlkem_cms/mlkem_priv.pem"));
        pOut.writeObject(kybKp.getPrivate());
        pOut.close();

        pOut = new JcaPEMWriter(new FileWriter("/tmp/mlkem_cms/mlkem_cert.pem"));
        pOut.writeObject(cert);
        pOut.close();

        pOut = new JcaPEMWriter(new FileWriter("/tmp/mlkem_cms/mlkem_cert.pem"));
        pOut.writeObject(caCert);
        pOut.close();
//
//        System.err.println(ASN1Dump.dumpAsString(receivedEnvelope.toASN1Structure()));

        RecipientInformationStore recipients = receivedEnvelope.getRecipientInfos();
//                System.err.println(ASN1Dump.dumpAsString(ASN1Primitive.fromByteArray(receivedEnvelope.getEncoded())));
        Collection c = recipients.getRecipients();

        assertEquals(1, c.size());

        RecipientInformation recInfo = (RecipientInformation)c.iterator().next();

        assertEquals(recInfo.getKeyEncryptionAlgOID(), NISTObjectIdentifiers.id_alg_ml_kem_768.getId());

        byte[] recData = recInfo.getContent(new JceKEMEnvelopedRecipient(kybKp.getPrivate()).setProvider("BC"));

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

    public void testMlKemRequestWithMlDsaCADirect()
        throws Exception
    {
        char[] senderMacPassword = "secret".toCharArray();
        GeneralName client = new GeneralName(new X500Name("CN=ML-KEM Subject"));
        GeneralName issuerCA = new GeneralName(new X500Name("CN=ML-DSA Issuer"));

        KeyPairGenerator dilKpGen = KeyPairGenerator.getInstance("ML-DSA", "BC");

        dilKpGen.initialize(MLDSAParameterSpec.ml_dsa_65);

        KeyPair dilKp = dilKpGen.generateKeyPair();

        X509CertificateHolder caCert = makeV3Certificate("CN=ML-DSA Issuer", dilKp);

        KeyPairGenerator kybKpGen = KeyPairGenerator.getInstance("ML-KEM", "BC");

        kybKpGen.initialize(MLKEMParameterSpec.ml_kem_768);

        KeyPair mlKemKp = kybKpGen.generateKeyPair();

        // initial request

        JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigIntegers.ONE);

        certReqBuild
            .setPublicKey(mlKemKp.getPublic())
            .setSubject(X500Name.getInstance(client.getName()))
            .setProofOfPossessionSubsequentMessage(SubsequentMessage.challengeResp);

        CertificateReqMessagesBuilder certReqMsgsBldr = new CertificateReqMessagesBuilder();

        certReqMsgsBldr.addRequest(certReqBuild.build());

        MacCalculator senderMacCalculator = new JcePBMac1CalculatorBuilder("HmacSHA256", 256).setProvider("BC").build(senderMacPassword);

        ProtectedPKIMessage message = new ProtectedPKIMessageBuilder(client, issuerCA)
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

        SecureRandom rand = new SecureRandom();
        CertificateRepMessageBuilder repMessageBuilder = new CertificateRepMessageBuilder(caCert);

        //
        // Send back an encryptedChallenge
        //
        // note: use cert req ID as key ID, don't want to use issuer/serial in this case!
        DigestCalculator owfCalc = new JcaDigestCalculatorProviderBuilder().build().get(DigestCalculator.SHA_256);
        JceKEMRecipientInfoGenerator recipientGenerator = new JceKEMRecipientInfoGenerator(senderReqMessage.getCertReqId().getEncoded(),
            new JcaPEMKeyConverter().setProvider("BC").getPublicKey(certTemplate.getPublicKey()), CMSAlgorithm.AES256_WRAP).setKDF(
            new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake256));

        byte[] A = new byte[32];
        rand.nextBytes(A);

        POPODecryptionKeyChallengeContentBuilder popoBldr = new POPODecryptionKeyChallengeContentBuilder(owfCalc, CMSAlgorithm.AES128_CBC);

        popoBldr.addChallenge(recipientGenerator, issuerCA, A);
        
        ContentSigner signer = new JcaContentSignerBuilder("ML-DSA").setProvider("BC").build(dilKp.getPrivate());
        ProtectedPKIMessage challengePkixMessage = new ProtectedPKIMessageBuilder(issuerCA, client)
                .setBody(popoBldr.build())
                .build(signer);

        assertEquals(PKIBody.TYPE_POPO_CHALL, challengePkixMessage.getBody().getType());
        assertTrue(challengePkixMessage.verify(new JcaContentVerifierProviderBuilder().setProvider("BC").build(dilKp.getPublic())));

        //
        // send back the decrypted challenge
        //
        DigestCalculatorProvider owfProvider = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
        POPODecryptionKeyChallengeContent popoDecKeyChallContent = POPODecryptionKeyChallengeContent.fromPKIBody(challengePkixMessage.getBody(), owfProvider);

        ChallengeContent[] challenges = popoDecKeyChallContent.toChallengeArray();

        byte[] challengeValue = challenges[0].extractChallenge(
            challengePkixMessage.getHeader(), new JceKEMEnvelopedRecipient(mlKemKp.getPrivate()).setProvider("BC"));

        POPODecryptionKeyResponseContentBuilder popoRespBldr = new POPODecryptionKeyResponseContentBuilder();

        popoRespBldr.addChallengeResponse(challengeValue);

        ProtectedPKIMessage challengeResponseMessage = new ProtectedPKIMessageBuilder(client, issuerCA)
             .setBody(popoRespBldr.build())
             .build(senderMacCalculator);

        assertEquals(PKIBody.TYPE_POPO_REP, challengeResponseMessage.getBody().getType());
        assertTrue(message.verify(macCalcProvider, senderMacPassword));
        assertTrue(Arrays.equals(A, POPODecryptionKeyResponseContent.fromPKIBody(challengeResponseMessage.getBody()).getResponses()[0]));

        //
        // So far so good, we'll produce and send the certificate
        //
        X509CertificateHolder cert = makeV3Certificate(certTemplate.getPublicKey(), certTemplate.getSubject(), dilKp, "CN=ML-DSA Issuer");

        CertificateResponseBuilder certRespBuilder = new CertificateResponseBuilder(senderReqMessage.getCertReqId(), new PKIStatusInfo(PKIStatus.granted));

        certRespBuilder.withCertificate(cert);

        repMessageBuilder = new CertificateRepMessageBuilder(caCert);

        repMessageBuilder.addCertificateResponse(certRespBuilder.build());

        signer = new JcaContentSignerBuilder("ML-DSA").setProvider("BC").build(dilKp.getPrivate());
        
        ProtectedPKIMessage responsePkixMessage = new ProtectedPKIMessageBuilder(issuerCA, client)
            .setBody(PKIBody.TYPE_INIT_REP, repMessageBuilder.build())
            .build(signer);

        assertEquals(PKIBody.TYPE_INIT_REP, responsePkixMessage.getBody().getType());
        assertTrue(responsePkixMessage.verify(new JcaContentVerifierProviderBuilder().setProvider("BC").build(dilKp.getPublic())));

        CertificateRepMessage certRepMessage = CertificateRepMessage.fromPKIBody(responsePkixMessage.getBody());

        CertificateResponse certResp = certRepMessage.getResponses()[0];

        assertEquals(false, certResp.hasEncryptedCertificate());

        X509CertificateHolder receivedCert = new X509CertificateHolder(certResp.getCertificate().getX509v3PKCert());
        byte[] recData = certResp.getCertificate().getEncoded();

        assertEquals(true, Arrays.equals(new CMPCertificate(cert.toASN1Structure()).getEncoded(), recData));

        // confirmation message calculation - this isn't actually required as part of the protocol, other than
        // to allow the user to confirm they received the certificate. A CA could have published prior to this point.

        CertificateConfirmationContent content = new CertificateConfirmationContentBuilder()
            .addAcceptedCertificate(cert, BigInteger.ONE)
            .build(new JcaDigestCalculatorProviderBuilder().build());

        message = new ProtectedPKIMessageBuilder(client, issuerCA)
            .setBody(PKIBody.TYPE_CERT_CONFIRM, content)
            .build(senderMacCalculator);

        assertTrue(content.getStatusMessages()[0].isVerified(receivedCert, new JcaDigestCalculatorProviderBuilder().build()));
        assertEquals(PKIBody.TYPE_CERT_CONFIRM, message.getBody().getType());

        // confirmation receiving

        CertificateConfirmationContent recContent = CertificateConfirmationContent.fromPKIBody(message.getBody());

        assertTrue(recContent.getStatusMessages()[0].isVerified(receivedCert, new JcaDigestCalculatorProviderBuilder().build()));
    }

    public void testNTRURequestWithMlDsaCA()
        throws Exception
    {
        char[] senderMacPassword = "secret".toCharArray();
        GeneralName sender = new GeneralName(new X500Name("CN=NTRU Subject"));
        GeneralName recipient = new GeneralName(new X500Name("CN=ML-DSA Issuer"));

        KeyPairGenerator dilKpGen = KeyPairGenerator.getInstance("ML-DSA", "BC");

        dilKpGen.initialize(MLDSAParameterSpec.ml_dsa_44);

        KeyPair dilKp = dilKpGen.generateKeyPair();

        X509CertificateHolder caCert = makeV3Certificate("CN=ML-DSA Issuer", dilKp);

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

        X509CertificateHolder cert = makeV3Certificate(certTemplate.getPublicKey(), certTemplate.getSubject(), dilKp, "CN=ML-DSA Issuer");

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

        ContentSigner signer = new JcaContentSignerBuilder("ML-DSA").setProvider("BC").build(dilKp.getPrivate());

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

    public void testBIKERequestWithMlDsaCA()
        throws Exception
    {
        char[] senderMacPassword = "secret".toCharArray();
        GeneralName sender = new GeneralName(new X500Name("CN=Bike128 Subject"));
        GeneralName recipient = new GeneralName(new X500Name("CN=ML-DSA Issuer"));

        KeyPairGenerator dilKpGen = KeyPairGenerator.getInstance("ML-DSA", "BC");

        dilKpGen.initialize(MLDSAParameterSpec.ml_dsa_44);

        KeyPair dilKp = dilKpGen.generateKeyPair();

        X509CertificateHolder caCert = makeV3Certificate("CN=ML-DSA Issuer", dilKp);

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

        X509CertificateHolder cert = makeV3Certificate(certTemplate.getPublicKey(), certTemplate.getSubject(), dilKp, "CN=ML-DSA Issuer");

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

        ContentSigner signer = new JcaContentSignerBuilder("ML-DSA").setProvider("BC").build(dilKp.getPrivate());

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

    public void testHQCRequestWithMlDsaCA()
        throws Exception
    {
        char[] senderMacPassword = "secret".toCharArray();
        GeneralName sender = new GeneralName(new X500Name("CN=HQC128 Subject"));
        GeneralName recipient = new GeneralName(new X500Name("CN=ML-DSA Issuer"));

        KeyPairGenerator dilKpGen = KeyPairGenerator.getInstance("ML-DSA", "BC");

        dilKpGen.initialize(MLDSAParameterSpec.ml_dsa_44);

        KeyPair dilKp = dilKpGen.generateKeyPair();

        X509CertificateHolder caCert = makeV3Certificate("CN=ML-DSA Issuer", dilKp);

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

        X509CertificateHolder cert = makeV3Certificate(certTemplate.getPublicKey(), certTemplate.getSubject(), dilKp, "CN=ML-DSA Issuer");

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

        ContentSigner signer = new JcaContentSignerBuilder("ML-DSA").setProvider("BC").build(dilKp.getPrivate());

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

    public void testCMCERequestWithMlDsaCA()
        throws Exception
    {
        char[] senderMacPassword = "secret".toCharArray();
        GeneralName sender = new GeneralName(new X500Name("CN=mceliece3488864 Subject"));
        GeneralName recipient = new GeneralName(new X500Name("CN=ML-DSA Issuer"));

        KeyPairGenerator dilKpGen = KeyPairGenerator.getInstance("ML-DSA", "BC");

        dilKpGen.initialize(MLDSAParameterSpec.ml_dsa_44);

        KeyPair dilKp = dilKpGen.generateKeyPair();

        X509CertificateHolder caCert = makeV3Certificate("CN=ML-DSA Issuer", dilKp);

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

        X509CertificateHolder cert = makeV3Certificate(certTemplate.getPublicKey(), certTemplate.getSubject(), dilKp, "CN=ML-DSA Issuer");

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

        ContentSigner signer = new JcaContentSignerBuilder("ML-DSA").setProvider("BC").build(dilKp.getPrivate());

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

    public void testExternalCMCERequestWithMlDsaCA()
            throws Exception
        {
            char[] senderMacPassword = "secret".toCharArray();
            GeneralName sender = new GeneralName(new X500Name("CN=mceliece3488864 Subject"));
            GeneralName recipient = new GeneralName(new X500Name("CN=ML-DSA Issuer"));

            KeyPairGenerator dilKpGen = KeyPairGenerator.getInstance("ML-DSA", "BC");

            dilKpGen.initialize(MLDSAParameterSpec.ml_dsa_44);

            KeyPair dilKp = dilKpGen.generateKeyPair();

            X509CertificateHolder caCert = makeV3Certificate("CN=ML-DSA Issuer", dilKp);

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

            X509CertificateHolder cert = makeV3Certificate(certTemplate.getPublicKey(), certTemplate.getSubject(), dilKp, "CN=ML-DSA Issuer");

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

            ContentSigner signer = new JcaContentSignerBuilder("ML-DSA").setProvider("BC").build(dilKp.getPrivate());

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

        ContentSigner signer = new JcaContentSignerBuilder("ML-DSA").build(issPriv);

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

        ContentSigner signer = new JcaContentSignerBuilder("ML-DSA").build(issPriv);

        X509CertificateHolder certHolder = certGen.build(signer);

        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder().build(issPub);

        assertTrue(certHolder.isSignatureValid(verifier));

        return certHolder;
    }
}
