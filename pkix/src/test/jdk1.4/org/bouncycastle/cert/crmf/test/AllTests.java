package org.bouncycastle.cert.crmf.test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import junit.framework.Assert;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers;
import org.bouncycastle.asn1.crmf.EncKeyWithID;
import org.bouncycastle.asn1.crmf.EncryptedValue;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.EncryptedValueBuilder;
import org.bouncycastle.cert.crmf.EncryptedValuePadder;
import org.bouncycastle.cert.crmf.EncryptedValueParser;
import org.bouncycastle.cert.crmf.PKIArchiveControl;
import org.bouncycastle.cert.crmf.PKMACBuilder;
import org.bouncycastle.cert.crmf.ValueDecryptorGenerator;
import org.bouncycastle.cert.crmf.bc.BcFixedLengthMGF1Padder;
import org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessage;
import org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessageBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcaEncryptedValueBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcaPKIArchiveControlBuilder;
import org.bouncycastle.cert.crmf.jcajce.JceAsymmetricValueDecryptorGenerator;
import org.bouncycastle.cert.crmf.jcajce.JceCRMFEncryptorBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcePKMACValuesCalculator;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JceAsymmetricKeyWrapper;
import org.bouncycastle.util.Arrays;

public class AllTests
    extends TestCase
{
    private static final byte[] TEST_DATA = "Hello world!".getBytes();
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final String PASSPHRASE = "hello world";

    /*
     *
     *  INFRASTRUCTURE
     *
     */

    public AllTests(String name)
    {
        super(name);
    }

    public static void main(String args[])
    {
        junit.textui.TestRunner.run(AllTests.class);
    }

    public static Test suite()
    {
        return new TestSuite(AllTests.class);
    }

    public void setUp()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public void tearDown()
    {

    }

    public void testBasicMessageWithArchiveControl()
        throws Exception
    {
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        KeyPair kp = kGen.generateKeyPair();
        X509Certificate cert = makeV1Certificate(kp, "CN=Test", kp, "CN=Test");

        JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigInteger.ONE);

        certReqBuild.setSubject(new X500Principal("CN=Test"))
                    .setPublicKey(kp.getPublic());

        certReqBuild.addControl(new JcaPKIArchiveControlBuilder(kp.getPrivate(), new X500Principal("CN=Test"))
            .addRecipientGenerator(new JceKeyTransRecipientInfoGenerator(cert).setProvider(BC))
            .build(new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier(CMSEnvelopedDataGenerator.AES128_CBC)).setProvider(BC).build()));

        JcaCertificateRequestMessage certReqMsg = new JcaCertificateRequestMessage(certReqBuild.build()).setProvider(BC);

        TestCase.assertEquals(new X500Principal("CN=Test"), certReqMsg.getSubjectX500Principal());
        TestCase.assertEquals(kp.getPublic(), certReqMsg.getPublicKey());

        checkCertReqMsgWithArchiveControl(kp, cert, certReqMsg);
        checkCertReqMsgWithArchiveControl(kp, cert, new JcaCertificateRequestMessage(certReqMsg.getEncoded()));
    }

    private void checkCertReqMsgWithArchiveControl(KeyPair kp, X509Certificate cert, JcaCertificateRequestMessage certReqMsg)
        throws CRMFException, CMSException, IOException
    {
        PKIArchiveControl archiveControl = (PKIArchiveControl)certReqMsg.getControl(CRMFObjectIdentifiers.id_regCtrl_pkiArchiveOptions);

        TestCase.assertEquals(PKIArchiveControl.encryptedPrivKey, archiveControl.getArchiveType());

        TestCase.assertTrue(archiveControl.isEnvelopedData());

        RecipientInformationStore recips = archiveControl.getEnvelopedData().getRecipientInfos();

        RecipientId recipientId = new JceKeyTransRecipientId(cert);

        RecipientInformation recipientInformation = recips.get(recipientId);

        TestCase.assertNotNull(recipientInformation);

        EncKeyWithID encKeyWithID = EncKeyWithID.getInstance(recipientInformation.getContent(new JceKeyTransEnvelopedRecipient(kp.getPrivate()).setProvider(BC)));

        TestCase.assertTrue(encKeyWithID.hasIdentifier());
        TestCase.assertFalse(encKeyWithID.isIdentifierUTF8String());

        TestCase.assertEquals(new GeneralName(X500Name.getInstance(new X500Principal("CN=Test").getEncoded())), encKeyWithID.getIdentifier());
        TestCase.assertTrue(Arrays.areEqual(kp.getPrivate().getEncoded(), encKeyWithID.getPrivateKey().getEncoded()));
    }

    public void testProofOfPossessionWithoutSender()
        throws Exception
    {
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        KeyPair kp = kGen.generateKeyPair();
        X509Certificate cert = makeV1Certificate(kp, "CN=Test", kp, "CN=Test");

        JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigInteger.ONE);

        certReqBuild.setPublicKey(kp.getPublic())
                    .setAuthInfoPKMAC(new PKMACBuilder(new JcePKMACValuesCalculator()), "fred".toCharArray())
                    .setProofOfPossessionSigningKeySigner(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(kp.getPrivate()));

        certReqBuild.addControl(new JcaPKIArchiveControlBuilder(kp.getPrivate(), new X500Principal("CN=test"))
            .addRecipientGenerator(new JceKeyTransRecipientInfoGenerator(cert).setProvider(BC))
            .build(new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier(CMSEnvelopedDataGenerator.AES128_CBC)).setProvider(BC).build()));

        JcaCertificateRequestMessage certReqMsg = new JcaCertificateRequestMessage(certReqBuild.build().getEncoded()).setProvider(BC);

        // check that internal check on popo signing is working okay
        try
        {
            certReqMsg.isValidSigningKeyPOP(new JcaContentVerifierProviderBuilder().setProvider(BC).build(kp.getPublic()));
            TestCase.fail("IllegalStateException not thrown");
        }
        catch (IllegalStateException e)
        {
            // ignore
        }

        TestCase.assertTrue(certReqMsg.isValidSigningKeyPOP(new JcaContentVerifierProviderBuilder().setProvider(BC).build(kp.getPublic()), new PKMACBuilder(new JcePKMACValuesCalculator().setProvider(BC)), "fred".toCharArray()));

        TestCase.assertEquals(kp.getPublic(), certReqMsg.getPublicKey());

        certReqMsg = new JcaCertificateRequestMessage(certReqBuild.build()).setProvider(BC);

                // check that internal check on popo signing is working okay
        try
        {
            certReqMsg.isValidSigningKeyPOP(new JcaContentVerifierProviderBuilder().setProvider(BC).build(kp.getPublic()));
            TestCase.fail("IllegalStateException not thrown");
        }
        catch (IllegalStateException e)
        {
            // ignore
        }

        TestCase.assertTrue(certReqMsg.isValidSigningKeyPOP(new JcaContentVerifierProviderBuilder().setProvider(BC).build(kp.getPublic()), new PKMACBuilder(new JcePKMACValuesCalculator().setProvider(BC)), "fred".toCharArray()));

        TestCase.assertEquals(kp.getPublic(), certReqMsg.getPublicKey());
    }

    public void testProofOfPossessionWithSender()
        throws Exception
    {
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        KeyPair kp = kGen.generateKeyPair();
        X509Certificate cert = makeV1Certificate(kp, "CN=Test", kp, "CN=Test");

        JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigInteger.ONE);

        certReqBuild.setPublicKey(kp.getPublic())
                    .setAuthInfoSender(new X500Principal("CN=Test"))
                    .setProofOfPossessionSigningKeySigner(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(kp.getPrivate()));

        certReqBuild.addControl(new JcaPKIArchiveControlBuilder(kp.getPrivate(), new X500Principal("CN=test"))
                                      .addRecipientGenerator(new JceKeyTransRecipientInfoGenerator(cert).setProvider(BC))
                                      .build(new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier(CMSEnvelopedDataGenerator.AES128_CBC)).setProvider(BC).build()));

        JcaCertificateRequestMessage certReqMsg = new JcaCertificateRequestMessage(certReqBuild.build().getEncoded());

        // check that internal check on popo signing is working okay
        try
        {
            certReqMsg.isValidSigningKeyPOP(new JcaContentVerifierProviderBuilder().setProvider(BC).build(kp.getPublic()), new PKMACBuilder(new JcePKMACValuesCalculator().setProvider(BC)), "fred".toCharArray());

            fail("IllegalStateException not thrown");
        }
        catch (IllegalStateException e)
        {
            // ignore
        }


        assertTrue(certReqMsg.isValidSigningKeyPOP(new JcaContentVerifierProviderBuilder().setProvider(BC).build(kp.getPublic())));

        assertEquals(kp.getPublic(), certReqMsg.getPublicKey());
    }

    public void testProofOfPossessionWithTemplate()
        throws Exception
    {
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        KeyPair kp = kGen.generateKeyPair();
        X509Certificate cert = makeV1Certificate(kp, "CN=Test", kp, "CN=Test");

        JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigInteger.ONE);

        certReqBuild.setPublicKey(kp.getPublic())
                    .setSubject(new X500Principal("CN=Test"))
                    .setAuthInfoSender(new X500Principal("CN=Test"))
                    .setProofOfPossessionSigningKeySigner(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(kp.getPrivate()));

        certReqBuild.addControl(new JcaPKIArchiveControlBuilder(kp.getPrivate(), new X500Principal("CN=test"))
                                      .addRecipientGenerator(new JceKeyTransRecipientInfoGenerator(cert).setProvider(BC))
                                      .build(new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier(CMSEnvelopedDataGenerator.AES128_CBC)).setProvider(BC).build()));

        JcaCertificateRequestMessage certReqMsg = new JcaCertificateRequestMessage(certReqBuild.build().getEncoded());

        assertTrue(certReqMsg.isValidSigningKeyPOP(new JcaContentVerifierProviderBuilder().setProvider(BC).build(kp.getPublic())));

        assertEquals(kp.getPublic(), certReqMsg.getPublicKey());
    }

    public void testKeySizes()
        throws Exception
    {
        verifyKeySize(NISTObjectIdentifiers.id_aes128_CBC, 128);
        verifyKeySize(NISTObjectIdentifiers.id_aes192_CBC, 192);
        verifyKeySize(NISTObjectIdentifiers.id_aes256_CBC, 256);

        verifyKeySize(NTTObjectIdentifiers.id_camellia128_cbc, 128);
        verifyKeySize(NTTObjectIdentifiers.id_camellia192_cbc, 192);
        verifyKeySize(NTTObjectIdentifiers.id_camellia256_cbc, 256);

        verifyKeySize(PKCSObjectIdentifiers.des_EDE3_CBC, 192);
    }

    private void verifyKeySize(ASN1ObjectIdentifier oid, int keySize)
        throws Exception
    {
        JceCRMFEncryptorBuilder encryptorBuilder = new JceCRMFEncryptorBuilder(oid).setProvider(BC);

        OutputEncryptor outputEncryptor = encryptorBuilder.build();

        Assert.assertEquals(keySize / 8, ((byte[])(outputEncryptor.getKey().getRepresentation())).length);
    }

    public void testEncryptedValue()
        throws Exception
    {
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        KeyPair kp = kGen.generateKeyPair();
        X509Certificate cert = makeV1Certificate(kp, "CN=Test", kp, "CN=Test");

        JcaEncryptedValueBuilder build = new JcaEncryptedValueBuilder(new JceAsymmetricKeyWrapper(cert.getPublicKey()).setProvider(BC), new JceCRMFEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(BC).build());
        EncryptedValue value = build.build(cert);
        ValueDecryptorGenerator decGen = new JceAsymmetricValueDecryptorGenerator(kp.getPrivate()).setProvider(BC);

        // try direct
        encryptedValueParserTest(value, decGen, cert);

        // try indirect
        encryptedValueParserTest(EncryptedValue.getInstance(value.getEncoded()), decGen, cert);
    }

    private void encryptedValueParserTest(EncryptedValue value, ValueDecryptorGenerator decGen, X509Certificate cert)
        throws Exception
    {
        EncryptedValueParser  parser = new EncryptedValueParser(value);

        X509CertificateHolder holder = parser.readCertificateHolder(decGen);

        assertTrue(Arrays.areEqual(cert.getEncoded(), holder.getEncoded()));
    }

    public void testEncryptedValuePassphrase()
        throws Exception
    {
        char[] passphrase = PASSPHRASE.toCharArray();
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        KeyPair kp = kGen.generateKeyPair();
        X509Certificate cert = makeV1Certificate(kp, "CN=Test", kp, "CN=Test");

        EncryptedValueBuilder build = new EncryptedValueBuilder(new JceAsymmetricKeyWrapper(cert.getPublicKey()).setProvider(BC), new JceCRMFEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(BC).build());
        EncryptedValue value = build.build(passphrase);
        ValueDecryptorGenerator decGen = new JceAsymmetricValueDecryptorGenerator(kp.getPrivate()).setProvider(BC);

        // try direct
        encryptedValuePassphraseParserTest(value, null, decGen, cert);

        // try indirect
        encryptedValuePassphraseParserTest(EncryptedValue.getInstance(value.getEncoded()), null, decGen, cert);
    }

    public void testEncryptedValuePassphraseWithPadding()
        throws Exception
    {
        char[] passphrase = PASSPHRASE.toCharArray();
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        KeyPair kp = kGen.generateKeyPair();
        X509Certificate cert = makeV1Certificate(kp, "CN=Test", kp, "CN=Test");

        BcFixedLengthMGF1Padder mgf1Padder = new BcFixedLengthMGF1Padder(200, new SecureRandom());
        EncryptedValueBuilder build = new EncryptedValueBuilder(new JceAsymmetricKeyWrapper(cert.getPublicKey()).setProvider(BC), new JceCRMFEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(BC).build(), mgf1Padder);
        EncryptedValue value = build.build(passphrase);
        ValueDecryptorGenerator decGen = new JceAsymmetricValueDecryptorGenerator(kp.getPrivate()).setProvider(BC);

        // try direct
        encryptedValuePassphraseParserTest(value, mgf1Padder, decGen, cert);

        // try indirect
        encryptedValuePassphraseParserTest(EncryptedValue.getInstance(value.getEncoded()), mgf1Padder, decGen, cert);
    }

    private void encryptedValuePassphraseParserTest(EncryptedValue value, EncryptedValuePadder padder, ValueDecryptorGenerator decGen, X509Certificate cert)
        throws Exception
    {
        EncryptedValueParser  parser = new EncryptedValueParser(value, padder);

        assertTrue(Arrays.areEqual(PASSPHRASE.toCharArray(), parser.readPassphrase(decGen)));
    }

    private static X509Certificate makeV1Certificate(KeyPair subKP, String _subDN, KeyPair issKP, String _issDN)
        throws GeneralSecurityException, IOException, OperatorCreationException
    {

        PublicKey subPub  = subKP.getPublic();
        PrivateKey issPriv = issKP.getPrivate();
        PublicKey  issPub  = issKP.getPublic();

        X509v1CertificateBuilder v1CertGen = new JcaX509v1CertificateBuilder(
            new X500Name(_issDN),
            BigInteger.valueOf(System.currentTimeMillis()),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
            new X500Name(_subDN),
            subPub);

        JcaContentSignerBuilder signerBuilder = null;

        if (issPub instanceof RSAPublicKey)
        {
            signerBuilder = new JcaContentSignerBuilder("SHA1WithRSA");
        }
        else if (issPub.getAlgorithm().equals("DSA"))
        {
            signerBuilder = new JcaContentSignerBuilder("SHA1withDSA");
        }
        else if (issPub.getAlgorithm().equals("ECDSA"))
        {
            signerBuilder = new JcaContentSignerBuilder("SHA1withECDSA");
        }
        else if (issPub.getAlgorithm().equals("ECGOST3410"))
        {
            signerBuilder = new JcaContentSignerBuilder("GOST3411withECGOST3410");
        }
        else
        {
            signerBuilder = new JcaContentSignerBuilder("GOST3411WithGOST3410");
        }

        signerBuilder.setProvider(BC);

        X509Certificate _cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(v1CertGen.build(signerBuilder.build(issPriv)));

        _cert.checkValidity(new Date());
        _cert.verify(issPub);

        return _cert;
    }
}