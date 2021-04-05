package org.bouncycastle.asn1.util.test;

import org.bouncycastle.asn1.cmc.test.*;
import org.bouncycastle.asn1.isismtt.test.AdditionalInformationSyntaxUnitTest;
import org.bouncycastle.asn1.isismtt.test.AdmissionSyntaxUnitTest;
import org.bouncycastle.asn1.isismtt.test.AdmissionsUnitTest;
import org.bouncycastle.asn1.isismtt.test.CertHashUnitTest;
import org.bouncycastle.asn1.isismtt.test.DeclarationOfMajorityUnitTest;
import org.bouncycastle.asn1.isismtt.test.MonetaryLimitUnitTest;
import org.bouncycastle.asn1.isismtt.test.NamingAuthorityUnitTest;
import org.bouncycastle.asn1.isismtt.test.ProcurationSyntaxUnitTest;
import org.bouncycastle.asn1.isismtt.test.RequestedCertificateUnitTest;
import org.bouncycastle.asn1.isismtt.test.RestrictionUnitTest;
import org.bouncycastle.asn1.smime.test.SMIMETest;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.Test;

public class RegressionTest
{
    public static Test[]    tests = {
        new BodyPartIDTest(),
        new BodyPartListTest(),
        new BodyPartPathTest(),
        new BodyPartReferenceTest(),
        new CMCCertificationRequestTest(),
        new CMCFailInfoTest(),
        new CMCPublicationInfoTest(),
        new CMCStatusInfoTest(),
        new CMCPublicationInfoTest(),
        new CMCStatusInfoTest(),
        new CMCStatusInfoV2Test(),
        new CMCStatusTest(),
        new CMCUnsignedDataTest(),
        new ControlsProcessedTest(),
        new DecryptedPOPTest(),
        new EncryptedPOPTest(),
        new ExtendedFailInfoTest(),
        new ExtensionReqTest(),
        new GetCertTest(),
        new GetCRLTest(),
        new IdentityProofV2Test(),
        new LraPopWitnessTest(),
        new ModCertTemplateTest(),
        new OtherMsgTest(),
        new OtherStatusInfoTest(),
        new PendInfoTest(),
        new PKIDataTest(),
        new PKIResponseTest(),
        new PopLinkWitnessV2Test(),
        new PublishTrustAnchorsTest(),
        new RevokeRequestTest(),
        new TaggedAttributeTest(),
        new TaggedCertificationRequestTest(),
        new TaggedContentInfoTest(),
        new TaggedRequestTest(),
        new AdditionalInformationSyntaxUnitTest(),
        new AdmissionsUnitTest(),
        new AdmissionSyntaxUnitTest(),
        new CertHashUnitTest(),
        new DeclarationOfMajorityUnitTest(),
        new MonetaryLimitUnitTest(),
        new NamingAuthorityUnitTest(),
        new ProcurationSyntaxUnitTest(),
        new RequestedCertificateUnitTest(),
        new RestrictionUnitTest(),
        new SMIMETest(),
    };

    public static void main(String[] args)
    {
        SimpleTest.runTests(tests);
    }
}
