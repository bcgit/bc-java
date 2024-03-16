package org.bouncycastle.cert.cmp.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.DSAParameterSpec;

import junit.framework.TestCase;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.SubsequentMessage;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
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
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.jcajce.spec.DHDomainParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.operator.PBEMacCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.operator.jcajce.JceAsymmetricKeyWrapper;
import org.bouncycastle.pkcs.jcajce.JcePBMac1CalculatorBuilder;
import org.bouncycastle.pkcs.jcajce.JcePBMac1CalculatorProviderBuilder;
import org.bouncycastle.util.BigIntegers;

public class ElgamalDSATest
    extends TestCase
{
    public void setUp()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public void tearDown()
    {

    }

    public void testElgamalWithDSA()
        throws Exception
    {
        char[] senderMacPassword = "secret".toCharArray();
        GeneralName sender = new GeneralName(new X500Name("CN=Elgamal Subject"));
        GeneralName recipient = new GeneralName(new X500Name("CN=DSA Issuer"));

        KeyPairGenerator dsaKpGen = KeyPairGenerator.getInstance("DSA", "BC");

        DSAParameters dsaParams = (DSAParameters)CryptoServicesRegistrar.getSizedProperty(CryptoServicesRegistrar.Property.DSA_DEFAULT_PARAMS, 2048);
        
        dsaKpGen.initialize(new DSAParameterSpec(dsaParams.getP(), dsaParams.getQ(), dsaParams.getG()));

        KeyPair dsaKp = dsaKpGen.generateKeyPair();

        X509CertificateHolder caCert = TestUtils.makeV3Certificate("CN=DSA Issuer", dsaKp);

        KeyPairGenerator elgKpGen = KeyPairGenerator.getInstance("Elgamal", "BC");

        elgKpGen.initialize(
            new DHDomainParameterSpec((DHParameters)CryptoServicesRegistrar.getSizedProperty(CryptoServicesRegistrar.Property.DH_DEFAULT_PARAMS, 2048)));
            
        KeyPair elgKp = elgKpGen.generateKeyPair();

        // initial request

        JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigIntegers.ONE);

        certReqBuild
            .setPublicKey(elgKp.getPublic())
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

        X509CertificateHolder cert = TestUtils.makeV3Certificate(certTemplate.getPublicKey(), certTemplate.getSubject(), dsaKp, "CN=DSA Issuer");

        // Send response with encrypted certificate
        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        // note: use cert req ID as key ID, don't want to use issuer/serial in this case!

        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(senderReqMessage.getCertReqId().getEncoded(),
                    new JceAsymmetricKeyWrapper(new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert))));

        CMSEnvelopedData encryptedCert = edGen.generate(
                                new CMSProcessableByteArray(new CMPCertificate(cert.toASN1Structure()).getEncoded()),
                                new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider("BC").build());

        CertificateResponseBuilder certRespBuilder = new CertificateResponseBuilder(senderReqMessage.getCertReqId(), new PKIStatusInfo(PKIStatus.granted));

        certRespBuilder.withCertificate(encryptedCert);

        CertificateRepMessageBuilder repMessageBuilder = new CertificateRepMessageBuilder(caCert);

        repMessageBuilder.addCertificateResponse(certRespBuilder.build());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withDSA").setProvider("BC").build(dsaKp.getPrivate());

        CertificateRepMessage repMessage = repMessageBuilder.build();

        ProtectedPKIMessage responsePkixMessage = new ProtectedPKIMessageBuilder(sender, recipient)
            .setBody(PKIBody.TYPE_INIT_REP, repMessage)
            .build(signer);

        // decrypt the certificate

        assertTrue(responsePkixMessage.verify(new JcaContentVerifierProviderBuilder().build(caCert)));

        CertificateRepMessage certRepMessage = CertificateRepMessage.fromPKIBody(responsePkixMessage.getBody());

        CertificateResponse certResp = certRepMessage.getResponses()[0];

        X509CertificateHolder receivedCert = new X509CertificateHolder(certResp.getCertificate(new JceKeyTransEnvelopedRecipient(elgKp.getPrivate())).getX509v3PKCert());

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

}
