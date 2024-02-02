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
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.EncryptedValue;
import org.bouncycastle.asn1.crmf.PKMACValue;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.crmf.SubsequentMessage;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.crmf.AuthenticatorControl;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.cert.crmf.Control;
import org.bouncycastle.cert.crmf.EncryptedValueBuilder;
import org.bouncycastle.cert.crmf.EncryptedValueParser;
import org.bouncycastle.cert.crmf.RegTokenControl;
import org.bouncycastle.cert.crmf.ValueDecryptorGenerator;
import org.bouncycastle.cert.crmf.bc.BcFixedLengthMGF1Padder;
import org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessage;
import org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessageBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcaEncryptedValueBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcaPKIArchiveControlBuilder;
import org.bouncycastle.cert.crmf.jcajce.JceAsymmetricValueDecryptorGenerator;
import org.bouncycastle.cert.crmf.jcajce.JceCRMFEncryptorBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.InputDecryptor;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JceAsymmetricKeyWrapper;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.test.GeneralTest;
import org.bouncycastle.util.Arrays;
import org.junit.Assert;

public class CrmfGeneralTest
    extends GeneralTest
{
    public static void main(String[] args)
        throws Exception
    {
        CrmfGeneralTest test = new CrmfGeneralTest();
        test.setUp();
        test.testEncryptedValuePassphraseWithPadding();
        test.testEncryptedValue();
        test.testBasicMessage();
    }

    public void testBasicMessage()
        throws Exception
    {
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        final KeyPair kp = kGen.generateKeyPair();

        final JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigInteger.ONE);
        // Tests for JcaCertificateRequestMessageBuilder, CertificateRequestMessageBuilder, and CertificateRequestMessage
        String subjectName = "CN=TestSubject";
        String issuerName = "CN=TestIssuer";
        String authInfoSenderName = "CN=TestAuthInfoSender";
        BigInteger serialNumber = BigInteger.ONE;
        X509Certificate cert = makeV1Certificate(kp, "CN=Test", kp, "CN=Test");
        Date date = new Date();
        certReqBuild
            //.setSubject(new X500Principal(subjectName))
            .setIssuer(new X500Principal(issuerName))
            .setPublicKey(kp.getPublic())
            .setSerialNumber(serialNumber)
            .setValidity(date, null)
//            .setRegInfo(atavArr)
            .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
            .addExtension(Extension.biometricInfo, false, new BasicConstraints(false).getEncoded())
            .setProofOfPossessionSigningKeySigner(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(kp.getPrivate()))
            .setAuthInfoSender(new X500Name(authInfoSenderName));

        JcaCertificateRequestMessage certReqMsg3 = new JcaCertificateRequestMessage(certReqBuild.build()).setProvider(new BouncyCastleProvider());
        assertFalse(certReqMsg3.hasControl(CRMFObjectIdentifiers.id_regCtrl_authenticator));
        assertNull(certReqMsg3.getControl(CRMFObjectIdentifiers.id_regCtrl_authenticator));

        certReqBuild.addControl(new JcaPKIArchiveControlBuilder(kp.getPrivate(), new X500Principal("CN=test"))
            .addRecipientGenerator(new JceKeyTransRecipientInfoGenerator(cert).setProvider(new BouncyCastleProvider()))
            .build(new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier(CMSEnvelopedDataGenerator.AES128_CBC)).setProvider(BC).build()));
        // source: https://blog.ejbca.org/2014/03/
        certReqBuild.addControl(new RegTokenControl("foo123"));
        certReqBuild.addControl(new AuthenticatorControl("test"));
        testException("only one proof of possession allowed", "IllegalStateException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                certReqBuild.setProofOfPossessionSubsequentMessage(SubsequentMessage.encrCert);
            }
        });

        testException("only one proof of possession allowed", "IllegalStateException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigInteger.ONE);
                certReqBuild
                    .setSerialNumber(new ASN1Integer(BigInteger.ONE))
                    .setProofOfPossessionSubsequentMessage(ProofOfPossession.TYPE_KEY_ENCIPHERMENT, SubsequentMessage.encrCert)
                    .setProofOfPossessionSigningKeySigner(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(kp.getPrivate()));
            }
        });

        testException("only one proof of possession allowed", "IllegalStateException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigInteger.ONE);
                certReqBuild
                    .setProofOfPossessionAgreeMAC(null)
                    .setProofOfPossessionSigningKeySigner(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(kp.getPrivate()))
                    .setProofOfPossessionSubsequentMessage(ProofOfPossession.TYPE_KEY_ENCIPHERMENT, SubsequentMessage.encrCert);
            }
        });

        testException("only one proof of possession allowed", "IllegalStateException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigInteger.ONE);
                certReqBuild
                    .setProofOfPossessionRaVerified()
                    .setProofOfPossessionSubsequentMessage(ProofOfPossession.TYPE_KEY_ENCIPHERMENT, SubsequentMessage.encrCert);
            }
        });

        testException("type must be ProofOfPossession.TYPE_KEY_ENCIPHERMENT or ProofOfPossession.TYPE_KEY_AGREEMENT", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigInteger.ONE);
                certReqBuild
                    .setProofOfPossessionSubsequentMessage(ProofOfPossession.TYPE_RA_VERIFIED, SubsequentMessage.encrCert);
            }
        });

        testException("only one proof of possession allowed", "IllegalStateException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigInteger.ONE);
                certReqBuild
                    .setProofOfPossessionSubsequentMessage(ProofOfPossession.TYPE_KEY_ENCIPHERMENT, SubsequentMessage.encrCert)
                    .setProofOfPossessionAgreeMAC(PKMACValue.getInstance(null));
            }
        });

        testException("only one proof of possession allowed", "IllegalStateException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigInteger.ONE);
                certReqBuild
                    .setProofOfPossessionSubsequentMessage(ProofOfPossession.TYPE_KEY_ENCIPHERMENT, SubsequentMessage.encrCert)
                    .setProofOfPossessionRaVerified();
            }
        });

        JcaCertificateRequestMessage certReqMsg = new JcaCertificateRequestMessage(certReqBuild.build()).setProvider(new BouncyCastleProvider());
        CertTemplate certTemplate = certReqMsg.getCertTemplate();
        assertEquals(certTemplate.getIssuer(), new X500Name(issuerName));
        assertEquals(certTemplate.getSerialNumber(), new ASN1Integer(serialNumber));
        assertEquals(certTemplate.getValidity().getNotBefore(), new Time(date));
        assertNull(certTemplate.getValidity().getNotAfter());
        assertNull(certReqMsg.getSubjectX500Principal());
        assertTrue(certReqMsg.hasControls());
        assertTrue(certReqMsg.hasControl(CRMFObjectIdentifiers.id_regCtrl_pkiArchiveOptions));
        assertNotNull(certTemplate.getExtensions().getExtension(Extension.basicConstraints));
        assertNotNull(certTemplate.getExtensions().getExtension(Extension.biometricInfo));

        CertificateRequestMessage certReqMsg2 = new CertificateRequestMessage(certReqMsg.getEncoded());
        assertTrue(certReqMsg2.hasProofOfPossession());
        assertEquals(certReqMsg2.getProofOfPossessionType(), CertificateRequestMessage.popSigningKey);
        assertFalse(certReqMsg2.hasSigningKeyProofOfPossessionWithPKMAC());

        // Tests for RegTokenControl
        Control regTokenControl = certReqMsg2.getControl(CRMFObjectIdentifiers.id_regCtrl_regToken);
        assertEquals(regTokenControl.getType(), CRMFObjectIdentifiers.id_regCtrl_regToken);
        assertEquals(regTokenControl.getValue(), new DERUTF8String("foo123"));

        // Tests for AuthenticatorControl
        Control authenticatorControl = certReqMsg2.getControl(CRMFObjectIdentifiers.id_regCtrl_authenticator);
        assertEquals(authenticatorControl.getType(), CRMFObjectIdentifiers.id_regCtrl_authenticator);
        assertEquals(authenticatorControl.getValue(), new DERUTF8String("test"));

    }

    public void testEncryptedValue()
        throws Exception
    {
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        final KeyPair kp = kGen.generateKeyPair();
        X509Certificate cert = makeV1Certificate(kp, "CN=Test", kp, "CN=Test");

        // Test for CRMFHelper
        testException("cannot create key generator:", "CRMFException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new JceCRMFEncryptorBuilder(CMSAlgorithm.IDEA_CBC, -1).setProvider(new BouncyCastlePQCProvider())
                    .setSecureRandom(CryptoServicesRegistrar.getSecureRandom()).build();
            }
        });

        JcaEncryptedValueBuilder build = new JcaEncryptedValueBuilder(
            new JceAsymmetricKeyWrapper(cert.getPublicKey()).setProvider(new BouncyCastleProvider()),
            new JceCRMFEncryptorBuilder(CMSAlgorithm.IDEA_CBC, -1).setProvider(new BouncyCastleProvider())
                .setSecureRandom(CryptoServicesRegistrar.getSecureRandom()).build());
        final EncryptedValue value = build.build(cert);


        testException("key invalid in message:", "CRMFException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                ValueDecryptorGenerator decGen = new JceAsymmetricValueDecryptorGenerator(kp.getPrivate()).setProvider(new BouncyCastlePQCProvider());
                EncryptedValueParser parser = new EncryptedValueParser(value);
                X509CertificateHolder holder = parser.readCertificateHolder(decGen);
            }
        });
        // try direct
//        encryptedValueParserTest(value, decGen, cert);
        ValueDecryptorGenerator decGen = new JceAsymmetricValueDecryptorGenerator(kp.getPrivate()).setProvider(new BouncyCastleProvider());

        EncryptedValueParser parser = new EncryptedValueParser(value);
        InputDecryptor decryptor = decGen.getValueDecryptor(value.getKeyAlg(),
            value.getSymmAlg(), value.getEncSymmKey().getBytes());
        assertEquals(decryptor.getAlgorithmIdentifier().getAlgorithm(), CMSAlgorithm.IDEA_CBC);
        X509CertificateHolder holder = parser.readCertificateHolder(decGen);

        assertTrue(Arrays.areEqual(cert.getEncoded(), holder.getEncoded()));
    }

    public void testEncryptedValuePassphraseWithPadding()
        throws Exception
    {
        final char[] passphrase = "hello world".toCharArray();
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        KeyPair kp = kGen.generateKeyPair();
        final X509Certificate cert = makeV1Certificate(kp, "CN=Test", kp, "CN=Test");

        final BcFixedLengthMGF1Padder mgf1Padder = new BcFixedLengthMGF1Padder(200);
        EncryptedValueBuilder build = new EncryptedValueBuilder(new JceAsymmetricKeyWrapper(cert.getPublicKey()).setProvider(BC),
            new JceCRMFEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(BC).build(), mgf1Padder);
        final EncryptedValue value = build.build(passphrase);


        final ValueDecryptorGenerator decGen = new JceAsymmetricValueDecryptorGenerator(kp.getPrivate()).setProvider(BC);

        EncryptedValueParser parser = new EncryptedValueParser(value, mgf1Padder);

        assertTrue(Arrays.areEqual(passphrase, parser.readPassphrase(decGen)));

        testException("bad padding in encoding", "IllegalStateException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                BcFixedLengthMGF1Padder mgf1Padder = new BcFixedLengthMGF1Padder(20);
                byte[] tmp = mgf1Padder.getUnpaddedData(new byte[21]);
            }
        });

        testException(null, "UnsupportedOperationException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                EncryptedValue value1 = new EncryptedValue(value.getIntendedAlg(), value.getSymmAlg(), value.getEncSymmKey(),
                    value.getKeyAlg(), new DEROctetString("test".getBytes()), value.getEncValue());
                EncryptedValueParser parser = new EncryptedValueParser(value1, mgf1Padder);
                parser.readCertificateHolder(decGen);
            }
        });
    }

    private static X509Certificate makeV1Certificate(KeyPair subKP, String _subDN, KeyPair issKP, String _issDN)
        throws GeneralSecurityException, IOException, OperatorCreationException
    {

        PublicKey subPub = subKP.getPublic();
        PrivateKey issPriv = issKP.getPrivate();
        PublicKey issPub = issKP.getPublic();

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
        else if (issPub.getAlgorithm().equals("EC"))
        {
            signerBuilder = new JcaContentSignerBuilder("SHA256withECDSA");
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
