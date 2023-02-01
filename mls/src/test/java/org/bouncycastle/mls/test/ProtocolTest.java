package org.bouncycastle.mls.test;

import junit.framework.TestSuite;
import org.bouncycastle.PrintTestResult;
import org.bouncycastle.mls.crypto.CipherSuite;
import org.bouncycastle.mls.protocol.PSKType;
import org.bouncycastle.mls.protocol.PreSharedKeyID;
import org.bouncycastle.mls.protocol.ResumptionPSKUsage;
import org.bouncycastle.util.encoders.Hex;

public class ProtocolTest
    extends CodecTest
{
    private final CipherSuite suite = new CipherSuite(CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);
    private final byte[] groupID = Hex.decode("00010203");
    private final long epoch = 0xA0A0A0A0A0A0A0A0L;
    private final byte[] pskID = Hex.decode("04050607");
    private final byte[] pskNonce = Hex.decode("08090a0b");

    PSKType valPSKType = PSKType.EXTERNAL;
    String encPSKType = "01";

    ResumptionPSKUsage valResumptionPSKUsage = ResumptionPSKUsage.REINIT;
    String encResumptionPSKUsage = "02";

    PreSharedKeyID valPSKIDExternal = PreSharedKeyID.external(pskID, pskNonce);
    String encPSKIDExternal = "0104040506070408090a0b";

    PreSharedKeyID valPSKIDResumption = PreSharedKeyID.resumption(valResumptionPSKUsage, groupID, epoch, pskNonce);
    String encPSKIDResumption = "02020400010203a0a0a0a0a0a0a0a00408090a0b";

    public void testWrite() throws Exception {
        doWriteTest(valPSKType, encPSKType);
        doWriteTest(valResumptionPSKUsage, encResumptionPSKUsage);
        doWriteTest(valPSKIDExternal, encPSKIDExternal);
        doWriteTest(valPSKIDResumption, encPSKIDResumption);
    }

    public static TestSuite suite()
    {
        return new TestSuite(ProtocolTest.class);
    }

    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }
}
