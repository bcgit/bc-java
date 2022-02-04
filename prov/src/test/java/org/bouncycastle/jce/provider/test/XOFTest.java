package org.bouncycastle.jce.provider.test;

import java.security.MessageDigest;
import java.security.Security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class XOFTest
    extends SimpleTest
{
    public String getName()
    {
        return "XOF";
    }

    private void tupleHashTest()
        throws Exception
    {
        MessageDigest tHash = MessageDigest.getInstance("TupleHash128", "BC");

        tHash.update(Hex.decode("000102"), 0, 3);
        tHash.update(Hex.decode("101112131415"), 0, 6);

        isTrue("oops!", Arrays.areEqual(Hex.decode("C5 D8 78 6C 1A FB 9B 82 11 1A B3 4B 65 B2 C0 04 8F A6 4E 6D 48 E2 63 26 4C E1 70 7D 3F FC 8E D1"), tHash.digest()));

        tHash = MessageDigest.getInstance("TupleHash256", "BC");

        tHash.update(Hex.decode("000102"), 0, 3);
        tHash.update(Hex.decode("101112131415"), 0, 6);

        isTrue("oops!", Arrays.areEqual(Hex.decode("CF B7 05 8C AC A5 E6 68 F8 1A 12 A2 0A 21 95 CE 97 A9 25 F1 DB A3 E7 44 9A 56 F8 22 01 EC 60 73 11 AC 26 96 B1 AB 5E A2 35 2D F1 42 3B DE 7B D4 BB 78 C9 AE D1 A8 53 C7 86 72 F9 EB 23 BB E1 94"), tHash.digest()));

    }

    private void parallelHashTest()
        throws Exception
    {
        MessageDigest pHash = MessageDigest.getInstance("ParallelHash128", "BC");

        byte[] data = Hex.decode("00 01 02 03 04 05 06 07 10 11 12 13 14 15 16 17 20 21 22 23 24 25 26 27");

        pHash.update(data, 0, data.length);

        isTrue("oops!", Arrays.areEqual(Hex.decode("04938219ecb09a30bbdbde1d7004007fa0c5b030421ae646e35e81c435bcc8e4"), pHash.digest()));

        pHash = MessageDigest.getInstance("ParallelHash256", "BC");

        data = Hex.decode("00 01 02 03 04 05 06 07 10 11 12 13 14 15 16 17 20 21 22 23 24 25 26 27");

        pHash.update(data, 0, data.length);

        isTrue("oops!", Arrays.areEqual(Hex.decode("76a2f391ae4b8ce24fcd54c5498d52dd3d3e9a325748a3b6e76ff1b1b2a0ecbccc31390499fa2435503026341eed5eb0c23cbbdcb73efd66305500ecb2788836"), pHash.digest()));
    }

    private void KMACTest()
        throws Exception
    {
        Mac kMac = Mac.getInstance("KMAC128", "BC");

        kMac.init(new SecretKeySpec(Hex.decode(
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F"), "KMAC"));

        kMac.update(Hex.decode("00010203"), 0, 4);

        isTrue(Arrays.areEqual(Hex.decode("E5780B0D3EA6F7D3A429C5706AA43A00FADBD7D49628839E3187243F456EE14E"), kMac.doFinal()));

        kMac = Mac.getInstance("KMAC256", "BC");

        kMac.init(new SecretKeySpec(Hex.decode(
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F"), "KMAC"));

        byte[] data = Hex.decode(
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1" +
                "F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3" +
                "E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5" +
                "D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7" +
                "C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9" +
                "B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9B" +
                "ABBBCBDBEBFC0C1C2C3C4C5C6C7");
        kMac.update(data, 0, data.length);

        isTrue("oops", Arrays.areEqual(Hex.decode("75358CF39E41494E949707927CEE0AF20A3FF553904C86B08F21CC414BCFD691589D27CF5E15369CBBFF8B9A4C2EB17800855D0235FF635DA82533EC6B759B69"), kMac.doFinal()));
    }

    public void performTest()
        throws Exception
    {
        tupleHashTest();
        parallelHashTest();
        KMACTest();
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new XOFTest());
    }
}
