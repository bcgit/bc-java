package org.bouncycastle.asn1.test;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;


/**
 * PKIFailureInfoTest
 */
public class PKIFailureInfoTest
    extends SimpleTest
{
    // A correct hex encoded BAD_DATA_FORMAT PKIFailureInfo 
    private static final byte[] CORRECT_FAILURE_INFO = Base64.decode("AwIANQ==");
    
    public String getName()
    {
        return "PKIFailureInfo";
    }
    
    private void testEncoding()
        throws IOException
    {
        DERBitString bitString = (DERBitString)new ASN1InputStream(CORRECT_FAILURE_INFO).readObject();
        PKIFailureInfo correct = new PKIFailureInfo(bitString);
                        
        PKIFailureInfo bug = new PKIFailureInfo(PKIFailureInfo.badRequest | PKIFailureInfo.badTime |PKIFailureInfo.badDataFormat | PKIFailureInfo.incorrectData);

        if (!areEqual(correct.getEncoded(ASN1Encoding.DER),bug.getEncoded(ASN1Encoding.DER)))
        {
            fail("encoding doesn't match");
        }
    }
    
    public void performTest()
        throws IOException
    {
        BitStringConstantTester.testFlagValueCorrect(0, PKIFailureInfo.badAlg);
        BitStringConstantTester.testFlagValueCorrect(1, PKIFailureInfo.badMessageCheck);
        BitStringConstantTester.testFlagValueCorrect(2, PKIFailureInfo.badRequest);
        BitStringConstantTester.testFlagValueCorrect(3, PKIFailureInfo.badTime);
        BitStringConstantTester.testFlagValueCorrect(4, PKIFailureInfo.badCertId);
        BitStringConstantTester.testFlagValueCorrect(5, PKIFailureInfo.badDataFormat);
        BitStringConstantTester.testFlagValueCorrect(6, PKIFailureInfo.wrongAuthority);
        BitStringConstantTester.testFlagValueCorrect(7, PKIFailureInfo.incorrectData);
        BitStringConstantTester.testFlagValueCorrect(8, PKIFailureInfo.missingTimeStamp);
        BitStringConstantTester.testFlagValueCorrect(9, PKIFailureInfo.badPOP);
        BitStringConstantTester.testFlagValueCorrect(10, PKIFailureInfo.certRevoked);
        BitStringConstantTester.testFlagValueCorrect(11, PKIFailureInfo.certConfirmed);
        BitStringConstantTester.testFlagValueCorrect(12, PKIFailureInfo.wrongIntegrity);
        BitStringConstantTester.testFlagValueCorrect(13, PKIFailureInfo.badRecipientNonce);
        BitStringConstantTester.testFlagValueCorrect(14, PKIFailureInfo.timeNotAvailable);
        BitStringConstantTester.testFlagValueCorrect(15, PKIFailureInfo.unacceptedPolicy);
        BitStringConstantTester.testFlagValueCorrect(16, PKIFailureInfo.unacceptedExtension);
        BitStringConstantTester.testFlagValueCorrect(17, PKIFailureInfo.addInfoNotAvailable);
        BitStringConstantTester.testFlagValueCorrect(18, PKIFailureInfo.badSenderNonce);
        BitStringConstantTester.testFlagValueCorrect(19, PKIFailureInfo.badCertTemplate);
        BitStringConstantTester.testFlagValueCorrect(20, PKIFailureInfo.signerNotTrusted);
        BitStringConstantTester.testFlagValueCorrect(21, PKIFailureInfo.transactionIdInUse);
        BitStringConstantTester.testFlagValueCorrect(22, PKIFailureInfo.unsupportedVersion);
        BitStringConstantTester.testFlagValueCorrect(23, PKIFailureInfo.notAuthorized);
        BitStringConstantTester.testFlagValueCorrect(24, PKIFailureInfo.systemUnavail);
        BitStringConstantTester.testFlagValueCorrect(25, PKIFailureInfo.systemFailure);
        BitStringConstantTester.testFlagValueCorrect(26, PKIFailureInfo.duplicateCertReq);

        testEncoding();
    }

    public static void main(
        String[]    args)
    {
        runTest(new PKIFailureInfoTest());
    }
}
