package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.ASN1Real;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestResult;
import org.junit.Assert;

import java.io.IOException;


public class ASN1RealTest   extends SimpleTest {

    public String getName()
    {
        return null;
    }

    public void performTest() throws Exception
    {

    }

    public void testConvert(){
//        byte[] target = Hex.decode("090380FE21");
//        ASN1Real realFromStr = ASN1Real.getInstance(target);
//        isEquals();
    }

    public void test1() throws IOException {
        double value = 8.25D;
        ASN1Real real = new ASN1Real(value);
        byte[] bin = real.getEncoded();
        double restore = new ASN1Real(bin).getValue();
        Assert.assertEquals(value, restore, 0.0000001);
    }

    @Override
    public TestResult perform()
    {

        test1();

        return super.perform();
    }

    public static void main(String[] args) {
        runTest(new ASN1RealTest(), System.out);
    }
}