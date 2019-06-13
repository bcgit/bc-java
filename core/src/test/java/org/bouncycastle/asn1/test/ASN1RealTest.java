package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.ASN1Real;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestResult;
import org.junit.Assert;

import java.io.IOException;


public class ASN1RealTest   extends SimpleTest {

    public String getName()
    {
        return "ASN1RealTest";
    }

    public void performTest() throws Exception
    {

    }

    public void testConvert(){
        byte[] target = Hex.decode("090380FE21");
        ASN1Real realFromStr = ASN1Real.getInstance(target);
        isEquals(8.25D, realFromStr.getValue());
    }

    public void test1() throws IOException {
        double value = 8.25D;
        ASN1Real real = new ASN1Real(value);
        byte[] bin = real.getEncoded();
        double restore =  ASN1Real.getInstance(bin).getValue();
        isEquals(value, restore);
    }

    public void test2() throws IOException {
        double value = 7.458151864318641D;
        ASN1Real real = new ASN1Real(value);
        byte[] bin = real.getEncoded();
        double restore =  ASN1Real.getInstance(bin).getValue();
        isEquals(value, restore);
    }
    public void test3() throws IOException {
        double value = -6558.7245d;
        ASN1Real real = new ASN1Real(value);
        byte[] bin = real.getEncoded();
        double restore =  ASN1Real.getInstance(bin).getValue();
        isEquals(value, restore);
    }
    @Override
    public TestResult perform()
    {

        try {
            test1();
            test2();
            test3();
            testConvert();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return super.perform();
    }

    public static void main(String[] args) {
        runTest(new ASN1RealTest(), System.out);
    }
}