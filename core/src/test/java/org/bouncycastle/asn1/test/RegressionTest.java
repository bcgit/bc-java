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
        new ASN1IntegerTest(),
        new DERUTF8StringTest(),
        new CertificateTest(),
        new GenerationTest(),
        new OCSPTest(),
        new OIDTest(),
        new RelativeOIDTest(),
        new PKCS10Test(),
        new PKCS12Test(),
        new X509NameTest(),
        new X500NameTest(),
        new X509ExtensionsTest(),
        new GeneralizedTimeTest(),
        new BitStringTest(),
        new MiscTest(),
        new X9Test(),
        new MonetaryValueUnitTest(),
        new BiometricDataUnitTest(),
        new Iso4217CurrencyCodeUnitTest(),
        new SemanticsInformationUnitTest(),
        new QCStatementUnitTest(),
        new TypeOfBiometricDataUnitTest(),
        new EncryptedPrivateKeyInfoTest(),
        new ReasonFlagsTest(),
        new NetscapeCertTypeTest(),
        new KeyUsageTest(),
        new StringTest(),
        new UTCTimeTest(),
        new NameOrPseudonymUnitTest(),
        new PersonalDataUnitTest(),
        new DERApplicationSpecificTest(),
        new IssuingDistributionPointUnitTest(),
        new TargetInformationTest(),
        new SubjectKeyIdentifierTest(),
        new ParsingTest(),
        new GeneralNameTest(),
        new ObjectIdentifierTest(),
        new RFC4519Test(),
        new PolicyConstraintsTest(),
        new PrivateKeyInfoTest(),
        new LocaleTest(),
        new LinkedCertificateTest(),
        new DLExternalTest(),
        new KMACParamsTest(),
        new DERPrivateTest(),
        new X509AltTest()
    };

    public static void main(String[] args)
    {
        SimpleTest.runTests(tests);
    }
}
