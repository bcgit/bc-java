package org.bouncycastle.asn1.test;

import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.Test;

public class RegressionTest
{
    public static Test[]    tests = {
        new InputStreamTest(),
        new EqualsAndHashCodeTest(),
        new TagTest(),
        new SetTest(),
        new DERUTF8StringTest(),
        new CertificateTest(),
        new GenerationTest(),
        new CMSTest(),
        new OCSPTest(),
        new OIDTest(),
        new PKCS10Test(),
        new PKCS12Test(),
        new X509NameTest(),
        new X500NameTest(),
        new X509ExtensionsTest(),
        new GeneralizedTimeTest(),
        new BitStringTest(),
        new MiscTest(),
        new SMIMETest(),
        new X9Test(),
        new MonetaryValueUnitTest(),
        new BiometricDataUnitTest(),
        new Iso4217CurrencyCodeUnitTest(),
        new SemanticsInformationUnitTest(),
        new QCStatementUnitTest(),
        new TypeOfBiometricDataUnitTest(),
        new SignerLocationUnitTest(),
        new CommitmentTypeQualifierUnitTest(),
        new CommitmentTypeIndicationUnitTest(),
        new EncryptedPrivateKeyInfoTest(),
        new DataGroupHashUnitTest(),
        new LDSSecurityObjectUnitTest(),
        // new CscaMasterListTest(),
        new AttributeTableUnitTest(),
        new ReasonFlagsTest(),
        new NetscapeCertTypeTest(),
        new PKIFailureInfoTest(),
        new KeyUsageTest(),
        new StringTest(),
        new UTCTimeTest(),
        new RequestedCertificateUnitTest(),
        new OtherCertIDUnitTest(),
        new OtherSigningCertificateUnitTest(),
        new ContentHintsUnitTest(),
        new CertHashUnitTest(),
        new AdditionalInformationSyntaxUnitTest(),
        new AdmissionSyntaxUnitTest(),
        new AdmissionsUnitTest(),
        new DeclarationOfMajorityUnitTest(),
        new ProcurationSyntaxUnitTest(),
        new ProfessionInfoUnitTest(),
        new RestrictionUnitTest(),
        new NamingAuthorityUnitTest(),
        new MonetaryLimitUnitTest(),
        new NameOrPseudonymUnitTest(),
        new PersonalDataUnitTest(),
        new DERApplicationSpecificTest(),
        new IssuingDistributionPointUnitTest(),
        new TargetInformationTest(),
        new SubjectKeyIdentifierTest(),
        new ESSCertIDv2UnitTest(),
        new ParsingTest(),
        new GeneralNameTest(),
        new RFC4519Test()
    };

    public static void main(String[] args)
    {
        SimpleTest.runTests(tests);
    }
}
