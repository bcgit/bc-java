package org.bouncycastle.its.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.its.ETSIEncryptedData;
import org.bouncycastle.its.ETSIEncryptedDataBuilder;
import org.bouncycastle.its.ETSIRecipientID;
import org.bouncycastle.its.ETSIRecipientInfo;
import org.bouncycastle.its.ETSIRecipientInfoBuilder;
import org.bouncycastle.its.ETSISignedData;
import org.bouncycastle.its.ETSISignedDataBuilder;
import org.bouncycastle.its.ITSCertificate;
import org.bouncycastle.its.ITSExplicitCertificateBuilder;
import org.bouncycastle.its.ITSImplicitCertificateBuilder;
import org.bouncycastle.its.ITSValidityPeriod;
import org.bouncycastle.its.bc.BcITSContentSigner;
import org.bouncycastle.its.bc.BcITSContentVerifierProvider;
import org.bouncycastle.its.bc.BcITSExplicitCertificateBuilder;
import org.bouncycastle.its.bc.BcITSPublicEncryptionKey;
import org.bouncycastle.its.jcajce.JcaETSIDataDecryptor;
import org.bouncycastle.its.jcajce.JcaITSContentSigner;
import org.bouncycastle.its.jcajce.JcaITSContentVerifierProvider;
import org.bouncycastle.its.jcajce.JcaITSExplicitCertificateBuilder;
import org.bouncycastle.its.jcajce.JcaITSImplicitCertificateBuilderBuilder;
import org.bouncycastle.its.jcajce.JcaITSPublicVerificationKey;
import org.bouncycastle.its.jcajce.JceETSIDataEncryptor;
import org.bouncycastle.its.jcajce.JceETSIKeyWrapper;
import org.bouncycastle.its.jcajce.JceITSPublicEncryptionKey;
import org.bouncycastle.its.operator.ETSIDataDecryptor;
import org.bouncycastle.its.operator.ETSIDataEncryptor;
import org.bouncycastle.its.operator.ITSContentSigner;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.oer.its.etsi102941.EtsiTs102941Data;
import org.bouncycastle.oer.its.etsi102941.InnerEcRequest;
import org.bouncycastle.oer.its.etsi102941.InnerEcRequestSignedForPop;
import org.bouncycastle.oer.its.ieee1609dot2.CertificateId;
import org.bouncycastle.oer.its.ieee1609dot2.EndEntityType;
import org.bouncycastle.oer.its.ieee1609dot2.IssuerIdentifier;
import org.bouncycastle.oer.its.ieee1609dot2.Opaque;
import org.bouncycastle.oer.its.ieee1609dot2.PsidGroupPermissions;
import org.bouncycastle.oer.its.ieee1609dot2.SequenceOfPsidGroupPermissions;
import org.bouncycastle.oer.its.ieee1609dot2.SignedData;
import org.bouncycastle.oer.its.ieee1609dot2.SubjectPermissions;
import org.bouncycastle.oer.its.ieee1609dot2.ToBeSignedCertificate;
import org.bouncycastle.oer.its.ieee1609dot2.VerificationKeyIndicator;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.BitmapSsp;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.CrlSeries;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EccP256CurvePoint;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EccP384CurvePoint;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId8;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Hostname;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Psid;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.PsidSsp;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.PsidSspRange;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.SequenceOfPsidSsp;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.SequenceOfPsidSspRange;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.ServiceSpecificPermissions;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.SubjectAssurance;
import org.bouncycastle.oer.its.template.etsi102941.EtsiTs102941MessagesCa;
import org.bouncycastle.oer.its.template.etsi102941.EtsiTs102941TypesEnrolment;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.test.GeneralTest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;

public class ITSGeneralTest
    extends GeneralTest
{
    public static void main(String[] args)
        throws Exception
    {
        ITSGeneralTest test = new ITSGeneralTest();
        test.setUp();
        test.testEncryptionNist();
        test.testDecryption();
        test.testImplicitBuilder2();
        test.testImplicitBuilder();
        test.testJcasecp256r1();
        test.testJcaecdsaBrainpoolP384r1();
        test.testJcaecdsaBrainpoolP256r1();
        test.testBc();
    }

    public void testBc()
        throws Exception
    {
        bcTest(SECObjectIdentifiers.secp256r1, 0);
        bcTest(TeleTrusTObjectIdentifiers.brainpoolP256r1, 1);
        bcTest(TeleTrusTObjectIdentifiers.brainpoolP384r1, 2);
        testException("unknown key type", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                bcTest(TeleTrusTObjectIdentifiers.brainpoolP160r1, 4);
            }
        });
    }

    private void bcTest(ASN1ObjectIdentifier identifier, int type)
        throws Exception
    {
        SecureRandom rand = new SecureRandom();
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        X9ECParameters parameters;
        if (identifier.equals(SECObjectIdentifiers.secp256r1))
        {
            parameters = NISTNamedCurves.getByOID(SECObjectIdentifiers.secp256r1);
        }
        else
        {
            parameters = TeleTrusTNamedCurves.getByOID(identifier);
        }
        generator.init(new ECKeyGenerationParameters(new ECNamedDomainParameters(identifier, parameters), rand));
        AsymmetricCipherKeyPair kp = generator.generateKeyPair();

        final ECPublicKeyParameters publicVerificationKey = (ECPublicKeyParameters)kp.getPublic();
        ECPrivateKeyParameters privateKeyParameters = (ECPrivateKeyParameters)kp.getPrivate();

        ToBeSignedCertificate.Builder tbsBuilder = new ToBeSignedCertificate.Builder();
        tbsBuilder.setAppPermissions(
            SequenceOfPsidSsp.builder()
                .setItem(PsidSsp.builder()
                    .setPsid(new Psid(622))
                    .setSsp(ServiceSpecificPermissions
                        .bitmapSsp(new BitmapSsp(new DEROctetString(Hex.decode("0101")))))
                    .createPsidSsp())
                .setItem(PsidSsp.builder()
                    .setPsid(new Psid(624))
                    .setSsp(ServiceSpecificPermissions.bitmapSsp(new BitmapSsp(new DEROctetString(Hex.decode("020138")))))
                    .createPsidSsp())
                .createSequenceOfPsidSsp()); // App Permissions
        tbsBuilder.setAssuranceLevel(new SubjectAssurance(new byte[]{(byte)0xC0}));
        // builder.setCanRequestRollover(OEROptional.ABSENT);
        tbsBuilder.setCertIssuePermissions(
            SequenceOfPsidGroupPermissions.builder()
                .addGroupPermission(PsidGroupPermissions.builder()
                    .setSubjectPermissions(
                        SubjectPermissions.explicit(
                            SequenceOfPsidSspRange.builder()
                                .add(PsidSspRange.builder()
                                    .setPsid(36).createPsidSspRange())
                                .add(PsidSspRange.builder()
                                    .setPsid(37).createPsidSspRange())
                                .add(PsidSspRange.builder()
                                    .setPsid(137).createPsidSspRange())
                                .add(PsidSspRange.builder()
                                    .setPsid(138).createPsidSspRange())
                                .add(PsidSspRange.builder()
                                    .setPsid(139).createPsidSspRange())
                                .add(PsidSspRange.builder()
                                    .setPsid(140).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(141).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(96).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(97).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(98).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(99).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(100).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(101).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(102).createPsidSspRange())
                                .build()
                        ))
                    .setMinChainLength(2)
                    .setChainLengthRange(0)
                    .setEeType(new EndEntityType(0xC0))

                    .createPsidGroupPermissions())
                .addGroupPermission(PsidGroupPermissions.builder()
                    .setSubjectPermissions(SubjectPermissions
                        .explicit(SequenceOfPsidSspRange.builder()
                            .add(PsidSspRange.builder()
                                .setPsid(623).createPsidSspRange())
                            .build())
                    )
                    .setMinChainLength(1)
                    .setChainLengthRange(0)
                    .setEeType(new EndEntityType(0xC0))
                    .createPsidGroupPermissions())
                .createSequenceOfPsidGroupPermissions());

        tbsBuilder.setCrlSeries(new CrlSeries(1));

        ITSContentSigner itsContentSigner = new BcITSContentSigner(new ECPrivateKeyParameters(privateKeyParameters.getD(),
            new ECNamedDomainParameters(identifier, privateKeyParameters.getParameters())));
        assertNull(itsContentSigner.getAssociatedCertificate());
        assertNotNull(itsContentSigner.getAssociatedCertificateDigest());
        final BcITSExplicitCertificateBuilder itsCertificateBuilder = new BcITSExplicitCertificateBuilder(itsContentSigner, tbsBuilder);

        itsCertificateBuilder.setValidityPeriod(ITSValidityPeriod.from(new Date()).plusYears(1));

        ITSCertificate newCert;
        if (identifier != TeleTrusTObjectIdentifiers.brainpoolP384r1)
        {
            newCert = itsCertificateBuilder.build(
                CertificateId.name(new Hostname("Legion of the BouncyCastle CA")),
                publicVerificationKey,
                publicVerificationKey);

            assertEquals(publicVerificationKey.getClass(), new BcITSPublicEncryptionKey(publicVerificationKey).getKey().getClass());
        }
        else
        {
            newCert = itsCertificateBuilder.build(
                CertificateId.name(new Hostname("Legion of the BouncyCastle CA")),
                publicVerificationKey);
            testException("unknown curve in public encryption key", "IllegalArgumentException", new TestExceptionOperation()
            {
                @Override
                public void operation()
                    throws Exception
                {
                    itsCertificateBuilder.build(
                        CertificateId.name(new Hostname("Legion of the BouncyCastle CA")),
                        publicVerificationKey,
                        publicVerificationKey);
                }
            });
        }


        ETSISignedDataBuilder signedDataBuilder = ETSISignedDataBuilder.builder(new Psid(10))
            .setUnsecuredData("The cat sat on the mat".getBytes());

        ETSISignedData signedData = signedDataBuilder.build(new BcITSContentSigner(privateKeyParameters, newCert));
        final BcITSContentVerifierProvider bcITSContentVerifierProvider = new BcITSContentVerifierProvider(newCert);
        assertEquals(bcITSContentVerifierProvider.getAssociatedCertificate(), newCert);
        assertTrue(bcITSContentVerifierProvider.hasAssociatedCertificate());
        assertTrue(signedData.signatureValid(bcITSContentVerifierProvider));
        assertNull(bcITSContentVerifierProvider.get(type).getAlgorithmIdentifier());
        testException("wrong verifier for algorithm: ", "OperatorCreationException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                bcITSContentVerifierProvider.get(-1);
            }
        });

        // recode test
        signedData = new ETSISignedData(signedData.getEncoded());
        assertTrue(signedData.signatureValid(new BcITSContentVerifierProvider(newCert)));
    }

    public void testJcasecp256r1()
        throws Exception
    {

        JcaJceHelper helper = new ProviderJcaJceHelper(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME));

        KeyPairGenerator kpg = helper.createKeyPairGenerator("ECDSA");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();

        ECPublicKey publicVerificationKey = (ECPublicKey)kp.getPublic();
        ECPrivateKey privateKeyParameters = (ECPrivateKey)kp.getPrivate();


        ToBeSignedCertificate.Builder tbsBuilder = new ToBeSignedCertificate.Builder();
        tbsBuilder.setAppPermissions(
            SequenceOfPsidSsp.builder()
                .setItem(PsidSsp.builder()
                    .setPsid(new Psid(622))
                    .setSsp(ServiceSpecificPermissions.bitmapSsp(new BitmapSsp(new DEROctetString(Hex.decode("0101")))))
                    .createPsidSsp())
                .setItem(PsidSsp.builder()
                    .setPsid(new Psid(624))
                    .setSsp(ServiceSpecificPermissions.bitmapSsp(new BitmapSsp(new DEROctetString(Hex.decode("020138")))))
                    .createPsidSsp())
                .createSequenceOfPsidSsp()); // App Permissions
        tbsBuilder.setAssuranceLevel(new SubjectAssurance(new byte[]{(byte)0xC0}));
        // builder.setCanRequestRollover(OEROptional.ABSENT);
        tbsBuilder.setCertIssuePermissions(
            SequenceOfPsidGroupPermissions.builder()
                .addGroupPermission(PsidGroupPermissions.builder()
                    .setSubjectPermissions(
                        SubjectPermissions.explicit(
                            SequenceOfPsidSspRange.builder()
                                .add(PsidSspRange.builder()
                                    .setPsid(36).createPsidSspRange())
                                .add(PsidSspRange.builder()
                                    .setPsid(37).createPsidSspRange())
                                .add(PsidSspRange.builder()
                                    .setPsid(137).createPsidSspRange())
                                .add(PsidSspRange.builder()
                                    .setPsid(138).createPsidSspRange())
                                .add(PsidSspRange.builder()
                                    .setPsid(139).createPsidSspRange())
                                .add(PsidSspRange.builder()
                                    .setPsid(140).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(141).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(96).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(97).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(98).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(99).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(100).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(101).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(102).createPsidSspRange())
                                .build()
                        ))
                    .setMinChainLength(2)
                    .setChainLengthRange(0)
                    .setEeType(new EndEntityType(0xC0))

                    .createPsidGroupPermissions())
                .addGroupPermission(PsidGroupPermissions.builder()
                    .setSubjectPermissions(SubjectPermissions
                        .explicit(SequenceOfPsidSspRange.builder()
                            .add(PsidSspRange.builder()
                                .setPsid(623)
                                .createPsidSspRange())
                            .build())
                    )
                    .setMinChainLength(1)
                    .setChainLengthRange(0)
                    .setEeType(new EndEntityType(0xC0))
                    .createPsidGroupPermissions())
                .createSequenceOfPsidGroupPermissions());

        tbsBuilder.setCrlSeries(new CrlSeries(1));

        ITSContentSigner itsContentSigner = new JcaITSContentSigner.Builder().build(privateKeyParameters);
        ITSExplicitCertificateBuilder itsCertificateBuilder = new JcaITSExplicitCertificateBuilder(itsContentSigner, tbsBuilder);
        assertNull(itsContentSigner.getAssociatedCertificate());
        assertNotNull(itsContentSigner.getAssociatedCertificateDigest());
        itsCertificateBuilder.setValidityPeriod(ITSValidityPeriod.from(new Date()).plusSixtyHours(10));

        JceITSPublicEncryptionKey jceITSPublicEncryptionKey = new JceITSPublicEncryptionKey.Builder().setProvider(BC).build(publicVerificationKey);
        ITSCertificate newCert = itsCertificateBuilder.build(
            CertificateId.name(new Hostname("Legion of the BouncyCastle CA")),
            new JcaITSPublicVerificationKey.Builder().setProvider(new BouncyCastleProvider()).build(publicVerificationKey),
            jceITSPublicEncryptionKey);
        assertEquals("EC", jceITSPublicEncryptionKey.getKey().getAlgorithm());
        itsContentSigner = new JcaITSContentSigner.Builder().build(privateKeyParameters, newCert);
        itsCertificateBuilder = new JcaITSExplicitCertificateBuilder(itsContentSigner, tbsBuilder);

        assertNotNull(newCert.getPublicEncryptionKey());

        newCert = itsCertificateBuilder.build(
            CertificateId.name(new Hostname("Legion of the BouncyCastle CA")),
            new JcaITSPublicVerificationKey.Builder().setProvider(new BouncyCastleProvider()).build(publicVerificationKey),
            jceITSPublicEncryptionKey);

        ITSValidityPeriod validityPeriod = new ITSValidityPeriod(newCert.getValidityPeriod().toASN1Structure());
        assertEquals(validityPeriod.getStartDate(), newCert.getValidityPeriod().getStartDate());

        ETSISignedDataBuilder signedDataBuilder = ETSISignedDataBuilder
            .builder(new Psid(10))
            .setUnsecuredData("The cat sat on the mat".getBytes());

        JcaITSContentSigner jcaITSContentSigner = new JcaITSContentSigner.Builder().build(privateKeyParameters, newCert);

        List list = new ArrayList<ITSCertificate>();
        list.add(newCert);
        ETSISignedData signedData = signedDataBuilder.build(jcaITSContentSigner, list);

        final JcaITSContentVerifierProvider jcaITSContentVerifierProvider = new JcaITSContentVerifierProvider.Builder()
            .setProvider("BC").build(newCert);
        assertTrue(jcaITSContentVerifierProvider.hasAssociatedCertificate());
        assertNotNull(jcaITSContentVerifierProvider.getAssociatedCertificate());
        assertTrue(
            signedData.signatureValid(
                jcaITSContentVerifierProvider));
        testException("wrong verifier for algorithm: ", "OperatorCreationException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                jcaITSContentVerifierProvider.get(-1);
            }
        });
    }

    public void testJcaecdsaBrainpoolP256r1()
        throws Exception
    {
        JcaJceHelper helper = new ProviderJcaJceHelper(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME));

        KeyPairGenerator kpg = helper.createKeyPairGenerator("ECDSA");
        kpg.initialize(new ECGenParameterSpec("brainpoolP256r1"));
        KeyPair kp = kpg.generateKeyPair();

        ECPublicKey publicVerificationKey = (ECPublicKey)kp.getPublic();
        ECPrivateKey privateKeyParameters = (ECPrivateKey)kp.getPrivate();


        ToBeSignedCertificate.Builder tbsBuilder = new ToBeSignedCertificate.Builder();
        tbsBuilder.setAppPermissions(
            SequenceOfPsidSsp.builder()
                .setItem(PsidSsp.builder()
                    .setPsid(new Psid(622))
                    .setSsp(ServiceSpecificPermissions.bitmapSsp(new BitmapSsp(new DEROctetString(Hex.decode("0101")))))
                    .createPsidSsp())
                .setItem(PsidSsp.builder()
                    .setPsid(new Psid(624))
                    .setSsp(ServiceSpecificPermissions.bitmapSsp(new BitmapSsp(new DEROctetString(Hex.decode("020138")))))
                    .createPsidSsp())
                .createSequenceOfPsidSsp()); // App Permissions
        tbsBuilder.setAssuranceLevel(new SubjectAssurance(new byte[]{(byte)0xC0}));
        // builder.setCanRequestRollover(OEROptional.ABSENT);
        tbsBuilder.setCertIssuePermissions(
            SequenceOfPsidGroupPermissions.builder()
                .addGroupPermission(PsidGroupPermissions.builder()
                    .setSubjectPermissions(
                        SubjectPermissions.explicit(
                            SequenceOfPsidSspRange.builder()
                                .add(PsidSspRange.builder()
                                    .setPsid(36).createPsidSspRange())
                                .add(PsidSspRange.builder()
                                    .setPsid(37).createPsidSspRange())
                                .add(PsidSspRange.builder()
                                    .setPsid(137).createPsidSspRange())
                                .add(PsidSspRange.builder()
                                    .setPsid(138).createPsidSspRange())
                                .add(PsidSspRange.builder()
                                    .setPsid(139).createPsidSspRange())
                                .add(PsidSspRange.builder()
                                    .setPsid(140).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(141).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(96).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(97).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(98).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(99).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(100).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(101).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(102).createPsidSspRange())
                                .build()
                        ))
                    .setMinChainLength(2)
                    .setChainLengthRange(0)
                    .setEeType(new EndEntityType(0xC0))

                    .createPsidGroupPermissions())
                .addGroupPermission(PsidGroupPermissions.builder()
                    .setSubjectPermissions(SubjectPermissions
                        .explicit(SequenceOfPsidSspRange.builder()
                            .add(PsidSspRange.builder()
                                .setPsid(623)
                                .createPsidSspRange())
                            .build())
                    )
                    .setMinChainLength(1)
                    .setChainLengthRange(0)
                    .setEeType(new EndEntityType(0xC0))
                    .createPsidGroupPermissions())
                .createSequenceOfPsidGroupPermissions());

        tbsBuilder.setCrlSeries(new CrlSeries(1));

        ITSContentSigner itsContentSigner = new JcaITSContentSigner.Builder().setProvider(new BouncyCastleProvider()).build(privateKeyParameters);
        JcaITSExplicitCertificateBuilder itsCertificateBuilder = new JcaITSExplicitCertificateBuilder(itsContentSigner, tbsBuilder)
            .setProvider(new BouncyCastleProvider());

        itsCertificateBuilder.setValidityPeriod(ITSValidityPeriod.from(new Date()).plusYears(1));

        JceITSPublicEncryptionKey jceITSPublicEncryptionKey = new JceITSPublicEncryptionKey.Builder().setProvider(new BouncyCastleProvider()).build(publicVerificationKey);
        ITSCertificate newCert = itsCertificateBuilder.build(
            CertificateId.name(new Hostname("Legion of the BouncyCastle CA")),
            publicVerificationKey,
            publicVerificationKey);
        assertEquals("EC", jceITSPublicEncryptionKey.getKey().getAlgorithm());

        itsContentSigner = new JcaITSContentSigner.Builder().setProvider(new BouncyCastleProvider()).build(privateKeyParameters, newCert);
        itsCertificateBuilder = new JcaITSExplicitCertificateBuilder(itsContentSigner, tbsBuilder)
            .setProvider(new BouncyCastleProvider());
        newCert = itsCertificateBuilder.build(
            CertificateId.name(new Hostname("Legion of the BouncyCastle CA")),
            publicVerificationKey,
            publicVerificationKey);

        ETSISignedDataBuilder signedDataBuilder = ETSISignedDataBuilder
            .builder(new Psid(10))
            .setUnsecuredData("The cat sat on the mat".getBytes());

        JcaITSContentSigner jcaITSContentSigner = new JcaITSContentSigner.Builder().setProvider(BC).build(privateKeyParameters, newCert);

        ETSISignedData signedData = signedDataBuilder.build(jcaITSContentSigner);

        assertTrue(
            signedData.signatureValid(
                new JcaITSContentVerifierProvider.Builder()
                    .setProvider(new BouncyCastleProvider())
                    .build(newCert)));
    }

    public void testJcaecdsaBrainpoolP384r1()
        throws Exception
    {
        JcaJceHelper helper = new ProviderJcaJceHelper(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME));

        KeyPairGenerator kpg = helper.createKeyPairGenerator("ECDSA");
        kpg.initialize(new ECGenParameterSpec("brainpoolP384r1"));
        KeyPair kp = kpg.generateKeyPair();

        final ECPublicKey publicVerificationKey = (ECPublicKey)kp.getPublic();
        ECPrivateKey privateKeyParameters = (ECPrivateKey)kp.getPrivate();


        ToBeSignedCertificate.Builder tbsBuilder = new ToBeSignedCertificate.Builder();
        tbsBuilder.setAppPermissions(
            SequenceOfPsidSsp.builder()
                .setItem(PsidSsp.builder()
                    .setPsid(new Psid(622))
                    .setSsp(ServiceSpecificPermissions.bitmapSsp(new BitmapSsp(new DEROctetString(Hex.decode("0101")))))
                    .createPsidSsp())
                .setItem(PsidSsp.builder()
                    .setPsid(new Psid(624))
                    .setSsp(ServiceSpecificPermissions.bitmapSsp(new BitmapSsp(new DEROctetString(Hex.decode("020138")))))
                    .createPsidSsp())
                .createSequenceOfPsidSsp()); // App Permissions
        tbsBuilder.setAssuranceLevel(new SubjectAssurance(new byte[]{(byte)0xC0}));
        // builder.setCanRequestRollover(OEROptional.ABSENT);
        tbsBuilder.setCertIssuePermissions(
            SequenceOfPsidGroupPermissions.builder()
                .addGroupPermission(PsidGroupPermissions.builder()
                    .setSubjectPermissions(
                        SubjectPermissions.explicit(
                            SequenceOfPsidSspRange.builder()
                                .add(PsidSspRange.builder()
                                    .setPsid(36).createPsidSspRange())
                                .add(PsidSspRange.builder()
                                    .setPsid(37).createPsidSspRange())
                                .add(PsidSspRange.builder()
                                    .setPsid(137).createPsidSspRange())
                                .add(PsidSspRange.builder()
                                    .setPsid(138).createPsidSspRange())
                                .add(PsidSspRange.builder()
                                    .setPsid(139).createPsidSspRange())
                                .add(PsidSspRange.builder()
                                    .setPsid(140).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(141).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(96).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(97).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(98).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(99).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(100).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(101).createPsidSspRange())
                                .add(PsidSspRange.builder().setPsid(102).createPsidSspRange())
                                .build()
                        ))
                    .setMinChainLength(2)
                    .setChainLengthRange(0)
                    .setEeType(new EndEntityType(0xC0))

                    .createPsidGroupPermissions())
                .addGroupPermission(PsidGroupPermissions.builder()
                    .setSubjectPermissions(SubjectPermissions
                        .explicit(SequenceOfPsidSspRange.builder()
                            .add(PsidSspRange.builder()
                                .setPsid(623)
                                .createPsidSspRange())
                            .build())
                    )
                    .setMinChainLength(1)
                    .setChainLengthRange(0)
                    .setEeType(new EndEntityType(0xC0))
                    .createPsidGroupPermissions())
                .createSequenceOfPsidGroupPermissions());

        tbsBuilder.setCrlSeries(new CrlSeries(1));

        ITSContentSigner itsContentSigner = new JcaITSContentSigner.Builder().build(privateKeyParameters);
        final JcaITSExplicitCertificateBuilder itsCertificateBuilder = new JcaITSExplicitCertificateBuilder(itsContentSigner, tbsBuilder)
            .setProvider(BC);

        itsCertificateBuilder.setValidityPeriod(ITSValidityPeriod.from(new Date()).plusYears(1));

        ITSCertificate newCert = itsCertificateBuilder.build(
            CertificateId.name(new Hostname("Legion of the BouncyCastle CA")),
            publicVerificationKey);

        itsContentSigner = new JcaITSContentSigner.Builder().build(privateKeyParameters, newCert);
        JcaITSExplicitCertificateBuilder itsCertificateBuilder2 = new JcaITSExplicitCertificateBuilder(itsContentSigner, tbsBuilder)
            .setProvider(BC);

        newCert = itsCertificateBuilder2.build(
            CertificateId.name(new Hostname("Legion of the BouncyCastle CA")),
            publicVerificationKey);

        testException("unknown curve in public encryption key", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new JceITSPublicEncryptionKey.Builder().setProvider(BC).build(publicVerificationKey);
            }
        });

        testException("unknown curve in public encryption key", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                JcaJceHelper helper = new ProviderJcaJceHelper(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME));
                KeyPairGenerator kpg = helper.createKeyPairGenerator("ECDSA");
                kpg.initialize(new ECGenParameterSpec("brainpoolP160r1"));
                KeyPair kp = kpg.generateKeyPair();

                ECPublicKey publicVerificationKey = (ECPublicKey)kp.getPublic();
                ECPrivateKey privateKeyParameters = (ECPrivateKey)kp.getPrivate();
                ITSCertificate newCert = itsCertificateBuilder.build(
                    CertificateId.name(new Hostname("Legion of the BouncyCastle CA")),
                    new JcaITSPublicVerificationKey.Builder().setProvider(BC).build(publicVerificationKey));
            }
        });

        ETSISignedDataBuilder signedDataBuilder = ETSISignedDataBuilder
            .builder(new Psid(10))
            .setUnsecuredData("The cat sat on the mat".getBytes());

        JcaITSContentSigner jcaITSContentSigner = new JcaITSContentSigner.Builder().build(privateKeyParameters, newCert);

        ETSISignedData signedData = signedDataBuilder.build(jcaITSContentSigner);

        assertTrue(
            signedData.signatureValid(
                new JcaITSContentVerifierProvider.Builder()
                    .setProvider("BC")
                    .build(newCert)));
    }

    public void testImplicitBuilder()
        throws Exception
    {

        byte[] ca = Hex.decode("800300810038811B45545349205465737420524341204320636572746966696361746500000000001A5617008466A8C001028002026E810201018002027081030201380102A080010E80012482080301FFFC03FF0003800125820A0401FFFFFF04FF00000080018982060201E002FF1F80018A82060201C002FF3F80018B820E0601000000FFF806FF000000000780018C820A0401FFFFE004FF00001F00018D0001600001610001620001630001640001650001660102C0208001018002026F82060201FE02FF01C0808082A4C29A1DDE0E1AEA8D36858B59016A45DB4A4968A2D5A1073B8EABC842C1D5948080B58B1A7CE9848D3EC315C70183D08E6E8B21C0FDA15A7839445AEEA636C794BA4ED59903EADC60372A542D21D77BFFB3E65B5B8BA3FB14BCE7CDA91268B177BC");
        ITSCertificate caCert = ITSJcaJceBasicTest.loadCertificate(ca);


        byte[] parentData = caCert.getEncoded();
        Digest digest = SHA256Digest.newInstance();
        byte[] parentDigest = new byte[digest.getDigestSize()];

        digest.update(parentData, 0, parentData.length);

        digest.doFinal(parentDigest, 0);


        ToBeSignedCertificate.Builder tbsBuilder = new ToBeSignedCertificate.Builder();

        tbsBuilder.setAssuranceLevel(new SubjectAssurance(new byte[]{(byte)0xC0}));
        tbsBuilder.setVerifyKeyIndicator(new VerificationKeyIndicator(VerificationKeyIndicator.verificationKey, EccP256CurvePoint.uncompressedP256(BigInteger.ONE, BigIntegers.TWO)));
        // builder.setCanRequestRollover(OEROptional.ABSENT);

        ITSImplicitCertificateBuilder certificateBuilder = new JcaITSImplicitCertificateBuilderBuilder().setProvider(new BouncyCastleProvider()).build(caCert, tbsBuilder);

        certificateBuilder.setValidityPeriod(ITSValidityPeriod.from(new Date()).plusYears(1));

        certificateBuilder.setAppPermissions(
            PsidSsp.builder()
                .setPsid(new Psid(622))
                .setSsp(ServiceSpecificPermissions.bitmapSsp(new BitmapSsp(Hex.decode("0101"))))
                .createPsidSsp(),
            PsidSsp.builder()
                .setPsid(new Psid(624))
                .setSsp(ServiceSpecificPermissions
                    .bitmapSsp(new BitmapSsp(Hex.decode("020138")))
                )
                .createPsidSsp()); // App Permissions

        certificateBuilder.setCertIssuePermissions(
            PsidGroupPermissions.builder()
                .setSubjectPermissions(
                    SubjectPermissions.explicit(
                        SequenceOfPsidSspRange.builder()
                            .add(PsidSspRange.builder()
                                .setPsid(36).createPsidSspRange())
                            .add(PsidSspRange.builder()
                                .setPsid(37).createPsidSspRange())
                            .add(PsidSspRange.builder()
                                .setPsid(137).createPsidSspRange())
                            .add(PsidSspRange.builder()
                                .setPsid(138).createPsidSspRange())
                            .add(PsidSspRange.builder()
                                .setPsid(139).createPsidSspRange())
                            .add(PsidSspRange.builder()
                                .setPsid(140).createPsidSspRange())
                            .add(PsidSspRange.builder().setPsid(141).createPsidSspRange())
                            .add(PsidSspRange.builder().setPsid(96).createPsidSspRange())
                            .add(PsidSspRange.builder().setPsid(97).createPsidSspRange())
                            .add(PsidSspRange.builder().setPsid(98).createPsidSspRange())
                            .add(PsidSspRange.builder().setPsid(99).createPsidSspRange())
                            .add(PsidSspRange.builder().setPsid(100).createPsidSspRange())
                            .add(PsidSspRange.builder().setPsid(101).createPsidSspRange())
                            .add(PsidSspRange.builder().setPsid(102).createPsidSspRange())
                            .build()
                    ))
                .setMinChainLength(2)
                .setChainLengthRange(0)
                .setEeType(new EndEntityType(0xC0))
                .createPsidGroupPermissions(),
            PsidGroupPermissions.builder()
                .setSubjectPermissions(SubjectPermissions
                    .explicit(SequenceOfPsidSspRange.builder()
                        .add(PsidSspRange.builder()
                            .setPsid(623)
                            .createPsidSspRange())
                        .build())
                )
                .setMinChainLength(1)
                .setChainLengthRange(0)
                .setEeType(new EndEntityType(0xC0)).createPsidGroupPermissions());

        ITSCertificate cert = certificateBuilder.build(
            CertificateId
                .name(new Hostname("Legion of the BouncyCastle CA")), BigInteger.ONE, BigIntegers.TWO);

        ITSCertificate cert2 = certificateBuilder.build(
            CertificateId
                .name(new Hostname("Legion of the BouncyCastle CA")), null);

        IssuerIdentifier caIssuerIdentifier = IssuerIdentifier
            .sha256AndDigest(new HashedId8(Arrays.copyOfRange(parentDigest, parentDigest.length - 8, parentDigest.length)));
        assertTrue(Arrays.areEqual(cert.getEncoded(), cert2.getEncoded()));
        assertTrue(cert.getIssuer().equals(caIssuerIdentifier));

        VerificationKeyIndicator vki = cert.toASN1Structure().getToBeSigned().getVerifyKeyIndicator();
        assertEquals(vki.getChoice(), VerificationKeyIndicator.reconstructionValue);
        assertEquals(vki.getVerificationKeyIndicator(), EccP256CurvePoint.uncompressedP256(BigInteger.ONE, BigIntegers.TWO));
    }
    public void testImplicitBuilder2()
        throws Exception
    {

        byte[] ca = Hex.decode("800300810038811B45545349205465737420524341204320636572746966696361746500000000001A5617008466A8C001028002026E810201018002027081030201380102A080010E80012482080301FFFC03FF0003800125820A0401FFFFFF04FF00000080018982060201E002FF1F80018A82060201C002FF3F80018B820E0601000000FFF806FF000000000780018C820A0401FFFFE004FF00001F00018D0001600001610001620001630001640001650001660102C0208001018002026F82060201FE02FF01C0808082A4C29A1DDE0E1AEA8D36858B59016A45DB4A4968A2D5A1073B8EABC842C1D5948080B58B1A7CE9848D3EC315C70183D08E6E8B21C0FDA15A7839445AEEA636C794BA4ED59903EADC60372A542D21D77BFFB3E65B5B8BA3FB14BCE7CDA91268B177BC");
        ITSCertificate caCert = ITSJcaJceBasicTest.loadCertificate(ca);


        byte[] parentData = caCert.getEncoded();
        Digest digest = new SHA384Digest();
        byte[] parentDigest = new byte[digest.getDigestSize()];

        digest.update(parentData, 0, parentData.length);

        digest.doFinal(parentDigest, 0);


        ToBeSignedCertificate.Builder tbsBuilder = new ToBeSignedCertificate.Builder();

        tbsBuilder.setAssuranceLevel(new SubjectAssurance(new byte[]{(byte)0xC0}));
        // builder.setCanRequestRollover(OEROptional.ABSENT);

        ITSImplicitCertificateBuilder certificateBuilder = new JcaITSImplicitCertificateBuilderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caCert, tbsBuilder);
        VerificationKeyIndicator verificationKeyIndicator = new VerificationKeyIndicator(VerificationKeyIndicator.verificationKey, EccP384CurvePoint.uncompressedP384(BigInteger.ONE, BigIntegers.TWO));
        tbsBuilder.setVerifyKeyIndicator(verificationKeyIndicator);

        certificateBuilder.setValidityPeriod(ITSValidityPeriod.from(new Date()).plusYears(1));

        certificateBuilder.setAppPermissions(
            PsidSsp.builder()
                .setPsid(new Psid(622))
                .setSsp(ServiceSpecificPermissions.bitmapSsp(new BitmapSsp(Hex.decode("0101"))))
                .createPsidSsp(),
            PsidSsp.builder()
                .setPsid(new Psid(624))
                .setSsp(ServiceSpecificPermissions
                    .bitmapSsp(new BitmapSsp(Hex.decode("020138")))
                )
                .createPsidSsp()); // App Permissions

        certificateBuilder.setCertIssuePermissions(
            PsidGroupPermissions.builder()
                .setSubjectPermissions(
                    SubjectPermissions.explicit(
                        SequenceOfPsidSspRange.builder()
                            .add(PsidSspRange.builder()
                                .setPsid(36).createPsidSspRange())
                            .add(PsidSspRange.builder()
                                .setPsid(37).createPsidSspRange())
                            .add(PsidSspRange.builder()
                                .setPsid(137).createPsidSspRange())
                            .add(PsidSspRange.builder()
                                .setPsid(138).createPsidSspRange())
                            .add(PsidSspRange.builder()
                                .setPsid(139).createPsidSspRange())
                            .add(PsidSspRange.builder()
                                .setPsid(140).createPsidSspRange())
                            .add(PsidSspRange.builder().setPsid(141).createPsidSspRange())
                            .add(PsidSspRange.builder().setPsid(96).createPsidSspRange())
                            .add(PsidSspRange.builder().setPsid(97).createPsidSspRange())
                            .add(PsidSspRange.builder().setPsid(98).createPsidSspRange())
                            .add(PsidSspRange.builder().setPsid(99).createPsidSspRange())
                            .add(PsidSspRange.builder().setPsid(100).createPsidSspRange())
                            .add(PsidSspRange.builder().setPsid(101).createPsidSspRange())
                            .add(PsidSspRange.builder().setPsid(102).createPsidSspRange())
                            .build()
                    ))
                .setMinChainLength(2)
                .setChainLengthRange(0)
                .setEeType(new EndEntityType(0xC0))
                .createPsidGroupPermissions(),
            PsidGroupPermissions.builder()
                .setSubjectPermissions(SubjectPermissions
                    .explicit(SequenceOfPsidSspRange.builder()
                        .add(PsidSspRange.builder()
                            .setPsid(623)
                            .createPsidSspRange())
                        .build())
                )
                .setMinChainLength(1)
                .setChainLengthRange(0)
                .setEeType(new EndEntityType(0xC0)).createPsidGroupPermissions());

        ITSCertificate cert = certificateBuilder.build(
            CertificateId
                .name(new Hostname("Legion of the BouncyCastle CA")), null);
        ITSCertificate cert2 = certificateBuilder.build(
            CertificateId
                .name(new Hostname("Legion of the BouncyCastle CA")), BigInteger.ONE, BigIntegers.TWO);

        assertTrue(Arrays.areEqual(cert.getEncoded(), cert2.getEncoded()));
        IssuerIdentifier caIssuerIdentifier = IssuerIdentifier
            .sha384AndDigest(new HashedId8(Arrays.copyOfRange(parentDigest, parentDigest.length - 8, parentDigest.length)));

        assertTrue(cert.getIssuer().equals(caIssuerIdentifier));

        VerificationKeyIndicator vki = cert.toASN1Structure().getToBeSigned().getVerifyKeyIndicator();
        assertEquals(vki.getChoice(), VerificationKeyIndicator.reconstructionValue);
        assertEquals(vki.getVerificationKeyIndicator(), EccP384CurvePoint.uncompressedP384(BigInteger.ONE, BigIntegers.TWO));
    }

    public void testDecryption()
        throws Exception
    {


        byte[] item = Hex.decode("03820101826cc2023b5115003e8083996da81b76fbdcaae0289abddfaf2b7198\n" +
            "456dbe5495e58c7c61e32a2c2610ca49a6e39470e44e37f302da99da444426f3\n" +
            "68211d919a06c57b574647b97ccc5180eaf3a6736b866446b150131382011c1e\n" +
            "56af1083537123946957844cc5906698a777dddc317966a3920e16cfad39c697\n" +
            "7f28156bd849b57e33b2a9abd1caa8a08520084214b865a355f6d274c3a64694\n" +
            "b81b605b729c2a6fbe88c561e591a055713698d40cabe196b1c96fefccc05f97\n" +
            "7beef6ce3528950c0e05f1c43749fd06114641c0442d0c952eb2eb0fa6b6f0b3\n" +
            "142c6a7e170c2520edf79076c0b6000d4216af50a72955a28e48b0d5ba14b05e\n" +
            "3ed4e5220c8bcc207070f6738b3b6ecabe056584b971df2a515bccd129bb614d\n" +
            "2666a461542fa4c4d25a67a91bacda14fba0310cb937fa9d5d3351f17272eef2\n" +
            "b6e492c3d7a02df81befed05139ce58a9c7f5d2f24f8acd99c4f8a8adbdd6a53\n" +
            "5f89a8a406430d3a335caa563b35bbb0733379d58f9056d017fdd7");


        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");

        kpGen.initialize(new ECGenParameterSpec("P-256"), new FixedSecureRandom(Hex.decode("06EB0D8314ADC4C3564A8E721DF1372FF54B5C725D09E2E353F2D0A46003AB86")));

        final KeyPair kp = kpGen.generateKeyPair();

        ETSIEncryptedData edc = new ETSIEncryptedData(item);

        ETSIRecipientInfo info = edc.getRecipients().getMatches(new ETSIRecipientID(Hex.decode("6cc2023b5115003e"))).iterator().next();
        ETSIRecipientInfo info2 = new ETSIRecipientInfo(info.getRecipientInfo());
        assertEquals(edc.getEncryptedData(), info.getEncryptedData());
        assertNull(info2.getEncryptedData());



        ETSIDataDecryptor dec = JcaETSIDataDecryptor.builder(
            kp.getPrivate(),
            Hex.decode("843BA5DC059A5DD3A6BF81842991608C4CB980456B9DA26F6CC2023B5115003E")
        ).provider(new BouncyCastleProvider()).build();



        byte[] content = info.getContent(dec); // Will fail on bad tag otherwise

        assertEquals("d311371e8373bea1027e6ae573d6f1dd", Hex.toHexString(dec.getKey()));

        ETSISignedData signedData = new ETSISignedData(content);

        //
        //
        // signedData.signatureValid(...)


        final Opaque value = Opaque.getInstance(
            signedData
                .getSignedData()
                .getTbsData()
                .getPayload()
                .getData()
                .getContent()
                .getIeee1609Dot2Content());
        testException("EtsiTs103097Data-Signed did not have signed data content", "IllegalStateException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new ETSISignedData(value);
            }
        });

        EtsiTs102941Data data = Opaque.getValue(EtsiTs102941Data.class, EtsiTs102941MessagesCa.EtsiTs102941Data.build(), value);

        InnerEcRequestSignedForPop innerEcRequestSignedForPop = InnerEcRequestSignedForPop.getInstance(data.getContent().getEtsiTs102941DataContent());

        ETSISignedData innerDataSigned = new ETSISignedData(
            SignedData.getInstance(
                innerEcRequestSignedForPop.getContent().getIeee1609Dot2Content()
            ));

        //
        //
        // innerDataSigned.signatureValid(...)
        //


        Opaque innerEcOpaque = Opaque.getInstance(
            innerDataSigned
                .getSignedData()
                .getTbsData()
                .getPayload()
                .getData()
                .getContent()
                .getIeee1609Dot2Content());

        InnerEcRequest request = Opaque.getValue(InnerEcRequest.class, EtsiTs102941TypesEnrolment.InnerEcRequest.build(), innerEcOpaque);
        assertTrue(Arrays.areEqual(request.getItsId().getOctets(), Hex.decode("455453492d4954532d303031")));
    }

    public void testEncryptionNist()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");

        kpGen.initialize(new ECGenParameterSpec("P-256"), new FixedSecureRandom(Hex.decode("06EB0D8314ADC4C3564A8E721DF1372FF54B5C725D09E2E353F2D0A46003AB86")));

        //  kpGen.initialize(new ECGenParameterSpec("P-256"), new FixedSecureRandom(Hex.decode("06EB0D8314ADC4C3564A8E721DF1372FF54B5C725D09E2E353F2D0A46003AB86")));

        KeyPair kp = kpGen.generateKeyPair();

        final ETSIEncryptedDataBuilder builder = new ETSIEncryptedDataBuilder();

        JceETSIKeyWrapper keyWrapper = new JceETSIKeyWrapper.Builder((ECPublicKey)kp.getPublic(), Hex.decode("843BA5DC059A5DD3A6BF81842991608C4CB980456B9DA26F6CC2023B5115003E")).setProvider(new BouncyCastleProvider()).build();
        ETSIRecipientInfoBuilder recipientInfoBuilder = new ETSIRecipientInfoBuilder(keyWrapper, Hex.decode("6CC2023B5115003E"));
        builder.addRecipientInfoBuilder(recipientInfoBuilder);

        ETSIDataEncryptor encryptor = new JceETSIDataEncryptor.Builder().setProvider(new BouncyCastleProvider()).build();
        ETSIEncryptedData encryptedData = builder.build(encryptor, Strings.toByteArray("Hello World"));

        testException("No such algorithm: CCM", "RuntimeException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                ETSIDataEncryptor encryptor = new JceETSIDataEncryptor.Builder().setProvider(new BouncyCastlePQCProvider()).build();
                ETSIEncryptedData encryptedData = builder.build(encryptor, Strings.toByteArray("Hello World"));
            }
        });

        // recoding

        encryptedData = new ETSIEncryptedData(encryptedData.getEncoded());

        // decryption

        ETSIRecipientInfo info = encryptedData.getRecipients().getMatches(new ETSIRecipientID(Hex.decode("6cc2023b5115003e"))).iterator().next();

        ETSIDataDecryptor dec = JcaETSIDataDecryptor.builder(
            kp.getPrivate(),
            Hex.decode("843BA5DC059A5DD3A6BF81842991608C4CB980456B9DA26F6CC2023B5115003E")
        ).provider("BC").build();

        byte[] content = info.getContent(dec);

        assertEquals("Hello World", Strings.fromByteArray(content));

    }
}
