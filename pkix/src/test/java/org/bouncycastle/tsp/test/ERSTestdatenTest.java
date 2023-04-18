package org.bouncycastle.tsp.test;

import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.Date;

import junit.framework.TestCase;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.tsp.ers.ERSEvidenceRecord;
import org.bouncycastle.tsp.ers.ERSInputStreamData;
import org.bouncycastle.util.io.Streams;

public class ERSTestdatenTest
    extends TestCase
{
    public void testChain1ATS()
        throws Exception
    {
        ERSEvidenceRecord ers = new ERSEvidenceRecord(Streams.readAll(getTestData("Testdaten_ERS-Testool/rfc4998/1Chain1ATS", "BIN_ER.ers")), new JcaDigestCalculatorProviderBuilder().build());

        ers.validate(new JcaSimpleSignerInfoVerifierBuilder().build(ers.getSigningCertificate()));

        ers.validatePresent(new ERSInputStreamData(getTestData("Testdaten_ERS-Testool/rfc4998/1Chain1ATS", "BIN.bin")), new Date());
    }

    public void testChain2ATS()
        throws Exception
    {
        ERSEvidenceRecord ers = new ERSEvidenceRecord(Streams.readAll(getTestData("Testdaten_ERS-Testool/rfc4998/1Chain2ATS", "BIN_ER.ers")), new JcaDigestCalculatorProviderBuilder().build());

        ers.validate(new JcaSimpleSignerInfoVerifierBuilder().build(ers.getSigningCertificate()));

        ers.validatePresent(new ERSInputStreamData(getTestData("Testdaten_ERS-Testool/rfc4998/1Chain2ATS", "BIN.bin")), new Date());

        ers = new ERSEvidenceRecord(Streams.readAll(getTestData("Testdaten_ERS-Testool/rfc4998/1Chain2ATS", "testRenewal.ers")), new JcaDigestCalculatorProviderBuilder().build());

        ers.validate(new JcaSimpleSignerInfoVerifierBuilder().build(ers.getSigningCertificate()));
    }

    public void test2Chains3ATS()
        throws Exception
    {
        ERSEvidenceRecord ers = new ERSEvidenceRecord(Streams.readAll(getTestData("Testdaten_ERS-Testool/rfc4998/2Chains3ATS", "BIN_ER.ers")), new JcaDigestCalculatorProviderBuilder().build());

        ers.validate(new JcaSimpleSignerInfoVerifierBuilder().build(ers.getSigningCertificate()));

        ers.validatePresent(new ERSInputStreamData(getTestData("Testdaten_ERS-Testool/rfc4998/2Chains3ATS", "BIN.bin")), new Date());
    }

    private static InputStream getTestData(String homeDir, String file)
        throws FileNotFoundException
    {
        return TestResourceFinder.findTestResource("tsp/20170316_Testdaten/" + homeDir, file);
    }
}
