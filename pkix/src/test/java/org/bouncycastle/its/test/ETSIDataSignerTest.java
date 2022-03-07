package org.bouncycastle.its.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

import junit.framework.TestCase;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.its.ETSISignedData;
import org.bouncycastle.its.ETSISignedDataBuilder;
import org.bouncycastle.its.ITSCertificate;
import org.bouncycastle.its.ITSExplicitCertificateBuilder;
import org.bouncycastle.its.ITSValidityPeriod;
import org.bouncycastle.its.bc.BcITSContentSigner;
import org.bouncycastle.its.bc.BcITSContentVerifierProvider;
import org.bouncycastle.its.bc.BcITSExplicitCertificateBuilder;
import org.bouncycastle.its.jcajce.JcaITSContentSigner;
import org.bouncycastle.its.jcajce.JcaITSContentVerifierProvider;
import org.bouncycastle.its.jcajce.JcaITSExplicitCertificateBuilder;
import org.bouncycastle.its.jcajce.JcaITSPublicVerificationKey;
import org.bouncycastle.its.operator.ITSContentSigner;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.oer.its.ieee1609dot2.CertificateId;
import org.bouncycastle.oer.its.ieee1609dot2.EndEntityType;
import org.bouncycastle.oer.its.ieee1609dot2.PsidGroupPermissions;
import org.bouncycastle.oer.its.ieee1609dot2.SequenceOfPsidGroupPermissions;
import org.bouncycastle.oer.its.ieee1609dot2.SubjectPermissions;
import org.bouncycastle.oer.its.ieee1609dot2.ToBeSignedCertificate;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.BitmapSsp;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.CrlSeries;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Hostname;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Psid;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.PsidSsp;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.PsidSspRange;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.SequenceOfPsidSsp;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.SequenceOfPsidSspRange;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.ServiceSpecificPermissions;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.SubjectAssurance;
import org.bouncycastle.util.encoders.Hex;

public class ETSIDataSignerTest
    extends TestCase
{
    public void setUp()
        throws Exception
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testBc()
        throws Exception
    {

        SecureRandom rand = new SecureRandom();
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        X9ECParameters parameters = NISTNamedCurves.getByOID(SECObjectIdentifiers.secp256r1);
        generator.init(new ECKeyGenerationParameters(new ECNamedDomainParameters(SECObjectIdentifiers.secp256r1, parameters), rand));
        AsymmetricCipherKeyPair kp = generator.generateKeyPair();

        ECPublicKeyParameters publicVerificationKey = (ECPublicKeyParameters)kp.getPublic();
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

        ITSContentSigner itsContentSigner = new BcITSContentSigner(new ECPrivateKeyParameters(privateKeyParameters.getD(), new ECNamedDomainParameters(SECObjectIdentifiers.secp256r1, privateKeyParameters.getParameters())));
        BcITSExplicitCertificateBuilder itsCertificateBuilder = new BcITSExplicitCertificateBuilder(itsContentSigner, tbsBuilder);

        itsCertificateBuilder.setValidityPeriod(ITSValidityPeriod.from(new Date()).plusYears(1));

        ITSCertificate newCert = itsCertificateBuilder.build(
            CertificateId.name(new Hostname("Legion of the BouncyCastle CA")),
            publicVerificationKey);


        ETSISignedDataBuilder signedDataBuilder = ETSISignedDataBuilder.builder(new Psid(10))
            .setUnsecuredData("The cat sat on the mat".getBytes());

        ETSISignedData signedData = signedDataBuilder.build(new BcITSContentSigner(privateKeyParameters, newCert));
        assertTrue(signedData.signatureValid(new BcITSContentVerifierProvider(newCert)));

        // recode test
        signedData = new ETSISignedData(signedData.getEncoded());
        assertTrue(signedData.signatureValid(new BcITSContentVerifierProvider(newCert)));
    }

    public void testJca()
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
                    .setSsp(ServiceSpecificPermissions.bitmapSsp(new BitmapSsp( new DEROctetString(Hex.decode("020138")))))
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

        itsCertificateBuilder.setValidityPeriod(ITSValidityPeriod.from(new Date()).plusYears(1));

        ITSCertificate newCert = itsCertificateBuilder.build(
            CertificateId.name(new Hostname("Legion of the BouncyCastle CA")),
            new JcaITSPublicVerificationKey.Builder().build(publicVerificationKey));


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


}
