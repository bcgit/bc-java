package org.bouncycastle.crypto.test;

import java.io.StringReader;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.signers.DSASigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.util.OpenSSHPrivateKeyUtil;
import org.bouncycastle.crypto.util.OpenSSHPublicKeyUtil;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.test.SimpleTest;

public class OpenSSHKeyParsingTests
    extends SimpleTest
{
    private static SecureRandom secureRandom = new SecureRandom();

    String rsa1024Key =
          "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn\n"
        + "NhAAAAAwEAAQAAAIEA37C9iHf9kS3ekS8xVE4p5/bmA7Yc37gXqN10W6c53FzVMiT9ZzVm\n"
        + "GXqJCRTpLjlX4NgRGHK3nLwyrEhR5JmTrLAXfwb04y3AcdZWZwkZBiXR2rFToEnXNobrvG\n"
        + "gmXEshBvCq6kUcGWf1FnW4av0kbVRkfiAjM1aMae1KIwlNMDcAAAIIVPY+b1T2Pm8AAAAH\n"
        + "c3NoLXJzYQAAAIEA37C9iHf9kS3ekS8xVE4p5/bmA7Yc37gXqN10W6c53FzVMiT9ZzVmGX\n"
        + "qJCRTpLjlX4NgRGHK3nLwyrEhR5JmTrLAXfwb04y3AcdZWZwkZBiXR2rFToEnXNobrvGgm\n"
        + "XEshBvCq6kUcGWf1FnW4av0kbVRkfiAjM1aMae1KIwlNMDcAAAADAQABAAAAgCWqIc/HvH\n"
        + "dkjNRPaPP0EVRQm1xGnsgAvGMfnscL+k8jhnZiChUFxcJGgqp3zeeNmkFuwDoonsgSXEns\n"
        + "B3YBcf7SE//XNMGrGi2FAQTccoTm80NLY77wONST2DNPqxY5xTsTiOJx/DPnru84laq1ae\n"
        + "t7WiNZCxsmuC0sPYDAG515AAAAQQDzeUo4QQbByJ9JVS0zcj26HKwGZSxxVb1Flq2Y+w0W\n"
        + "E/4GuYvh3ujXlwEankjYUNGNI0/u0NCzuDPZzBx9LZdeAAAAQQD9TiakDmscY9Dd8bEBL+\n"
        + "cAhCHrdxtx9ND/793cQNkpm10NL0Fz4jXQfn2/Z7nLFKmMzJlQXzUHH/itzWg9s0MlAAAA\n"
        + "QQDiEe/BJMLRZ+94n98VCEr7E+eG2isQctxiAowH7o/wp5WAkFSD9W58dqUobuneXleG+F\n"
        + "DAfXzFhYvNE+TdLXUrAAAADm1hcmtAYmFybmFjbGVzAQIDBA==\n"
        + "-----END OPENSSH PRIVATE KEY-----\n";
      String rsa2048Key =
          "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + "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\n"
        + "-----END OPENSSH PRIVATE KEY-----\n";
      String rsa3072Key =
          "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\n"
        + "NhAAAAAwEAAQAAAYEA34VbMJbV2+ZJyRQANnFkTPNcSPkjBllNbnUrlGFQ9wxRyr6xiVRj\n"
        + "LrjIL+dXaJRhFNktI9191AJI9Eiq9+aWnrjH0/SB38L1MRcktuvBwraPO8K0Pj8A2FkqI0\n"
        + "uc/XrHLrkg7YbW/So1us1TppOYzuBtGzb8yg2/r+i3ghWT8+h7DWo55pTQGaTHnVyoPPqz\n"
        + "IDV9yt63tGeL9M3T+Ts9VIkidjV1XXqitkEtksB7cykt4AV0lkN1BWDNbt71YuYhLjDvTK\n"
        + "jzVq3MfYV91Ux9XaL2uF6pD+0kmn8oNEQ7VRAUFlno1/tsdp578vZDd/ycRfOy9GRLqJ5L\n"
        + "4mXBsbqxKH9wscHptMgDtqe8B7CxEgU5EZyp8zySPSlwPBebfnr1vemgH4GBfDOA1gZeTK\n"
        + "HxiWXXUZBMj+S/fJ1YFJ3c5L3ZcHoES3FiIEy2w7tAwfSubkKbP5Wx0hl5/gfM8bAwrPgj\n"
        + "MMMXR1yKozDbpAzqo2eb+mTkN6FK3U47leFEe3gVAAAFiHAYBoRwGAaEAAAAB3NzaC1yc2\n"
        + "EAAAGBAN+FWzCW1dvmSckUADZxZEzzXEj5IwZZTW51K5RhUPcMUcq+sYlUYy64yC/nV2iU\n"
        + "YRTZLSPdfdQCSPRIqvfmlp64x9P0gd/C9TEXJLbrwcK2jzvCtD4/ANhZKiNLnP16xy65IO\n"
        + "2G1v0qNbrNU6aTmM7gbRs2/MoNv6/ot4IVk/Poew1qOeaU0Bmkx51cqDz6syA1fcret7Rn\n"
        + "i/TN0/k7PVSJInY1dV16orZBLZLAe3MpLeAFdJZDdQVgzW7e9WLmIS4w70yo81atzH2Ffd\n"
        + "VMfV2i9rheqQ/tJJp/KDREO1UQFBZZ6Nf7bHaee/L2Q3f8nEXzsvRkS6ieS+JlwbG6sSh/\n"
        + "cLHB6bTIA7anvAewsRIFORGcqfM8kj0pcDwXm3569b3poB+BgXwzgNYGXkyh8Yll11GQTI\n"
        + "/kv3ydWBSd3OS92XB6BEtxYiBMtsO7QMH0rm5Cmz+VsdIZef4HzPGwMKz4IzDDF0dciqMw\n"
        + "26QM6qNnm/pk5DehSt1OO5XhRHt4FQAAAAMBAAEAAAGATJ9obTWnxiQhcx66G++vFHnwTs\n"
        + "uo6ApA8vaTo9/gY3ADsd7A+XTGM0QAy/sgCaejyAPS55KMCdtmqucmRKj1RR/O0KfmxZAN\n"
        + "gXCPk20qFNeELlZGd3gdkAyw1zyaaoJmOWwZD5PDqzGHDaxJWrcKERD6FfQ5oAIqjeDW12\n"
        + "8SMvClDio2AwdMdx33l8glnBHMyePMZXkHvH4qihbs7WkTUyFXgPI+c3cQxC1/s+jr6MRb\n"
        + "B4qXNtOVD+zpP3KK6AY/AY+hFEjXXTHMwPIAy5Thxt2QncmlgW73zSyvgoXMIxBRy2vni5\n"
        + "Y8LmcPQ+lkuZPJUXxf+7lb0m2qKav4Ey9FdaNVcBOw1Y1l3ZPGt3Uvd1+v8QikNzurNUuu\n"
        + "EBjaVBIjXjgGujTZRuEkpdblHDnoMoSha8JRkBFmokJJT/pF42BwptUHZ07tHT7dqn6zvQ\n"
        + "TRTq+HqAmOibx2mxp+aT5KtUuJA/krMNlhqlTKqvOFx/4t5kZ6ciYoVg/DZe717ONZAAAA\n"
        + "wCK0Mvik0w29hYEE+hsyLBFQ2CkEpKzvyyIVmckJGJ8zAjjhhs/XUrZGRiKD1swK36YGyd\n"
        + "+EnZ7gPATWo6CUJmIbkZvZ3hfVljXSvCHPwg8iGo1MiqHWY4MfIhOgVf/lKB7Mfuj9iF0i\n"
        + "WZK3bZvaFY3+uVfTtWO/JfcmWevLeALBDJztaGmO1IPpleh9FMSDa5fK0w3MJfHSAz/YUc\n"
        + "maU/1Hz/GdLzgaViewb7Me+Iys27d1YyPwbeXip/vaCPt7bAAAAMEA8+eoaMTJP6FLYC8a\n"
        + "IVFfx5OLw4xJo6xRNR2QvcNlneh+uvGK0wEwBnkAL9PURmlQEhFcQdSmIHGKQBUGpQ1Huw\n"
        + "ahWPlaSW9xau2vAvJH3oNoocak35fBfLjEI2UNpRHqhLST7aAe4sEw8xP+5khr/NptEk5C\n"
        + "X4mRq/4p8REm21tFZt8+VX2DtEKMlYqgAfacgcgV4i2aeo8CJJocH1magby5ZaHJIectAX\n"
        + "XHszQAm/CaRNWk7rYyjWLxZgASJ4a/AAAAwQDqmu0ZPlkyULFOk/iScA7vYbfnGWT4qC/m\n"
        + "I54sFDulMN847grXfbyri7kf57KBFXbCh7tQb1Xn947MEKu+ibchkntlKxgCJQzH6dxktq\n"
        + "yy49d+WLqfjYq1AyDIpgmcdu3pVc8Rxi4GpsHZG1DBf4H9Kc5hw9YnqYXhHHwINNWa07ry\n"
        + "xcxQuK2sGkRT7Q2NdfEQ9LG4GNIusJeISJgY9NdDBaXrSODSkJI2KCOxDlNY5NsNXXc0Ty\n"
        + "7fLQW04MPjqisAAAAObWFya0BiYXJuYWNsZXMBAgMEBQ==\n"
        + "-----END OPENSSH PRIVATE KEY-----\n";
      String rsa4096Key =
          "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + "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\n"
        + "-----END OPENSSH PRIVATE KEY-----\n";
      String ecdsa256Key =
          "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS\n"
        + "1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQS9VjynnoLGUcT2hXXPkFwGfbleI4Ln\n"
        + "1kkgt2UgibKXw9NtesSqpKdEBDW5Kh2nmqLCIk+fdbsTGkxlfaYBtUrkAAAAqBQCER8UAh\n"
        + "EfAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBL1WPKeegsZRxPaF\n"
        + "dc+QXAZ9uV4jgufWSSC3ZSCJspfD0216xKqkp0QENbkqHaeaosIiT591uxMaTGV9pgG1Su\n"
        + "QAAAAgbAJJUVcjwwU/olgrxgINJ1DViX6GcCBhgeH8wAXiNKoAAAAObWFya0BiYXJuYWNs\n"
        + "ZXMBAg==\n"
        + "-----END OPENSSH PRIVATE KEY-----\n";
      String ecdsa384Key =
          "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAiAAAABNlY2RzYS\n"
        + "1zaGEyLW5pc3RwMzg0AAAACG5pc3RwMzg0AAAAYQS0yKimt2kBeyNKUqNivPfSPBVyU4jH\n"
        + "9+6hNsRIJG4NKRgKdIOIiOOLm6pGLUmwN4yDS+0ssdPxwRthQzL879HRtwbqAAb1ShK0CT\n"
        + "rljAhk9+SUgrOqWnKL2Ngo1uU5KZgAAADYJC2IQSQtiEEAAAATZWNkc2Etc2hhMi1uaXN0\n"
        + "cDM4NAAAAAhuaXN0cDM4NAAAAGEEtMioprdpAXsjSlKjYrz30jwVclOIx/fuoTbESCRuDS\n"
        + "kYCnSDiIjji5uqRi1JsDeMg0vtLLHT8cEbYUMy/O/R0bcG6gAG9UoStAk65YwIZPfklIKz\n"
        + "qlpyi9jYKNblOSmYAAAAMQChvecXe7PGUVG0Pz2IgM9f80YLXdarf98sRptbGSIPwu8KlW\n"
        + "OlGv0Any5ue51/I5wAAAAObWFya0BiYXJuYWNsZXMB\n"
        + "-----END OPENSSH PRIVATE KEY-----\n";
      String ecdsa521Key =
          "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAArAAAABNlY2RzYS\n"
        + "1zaGEyLW5pc3RwNTIxAAAACG5pc3RwNTIxAAAAhQQA90An5exsl3UEU0d8fhqV8rgmoyzJ\n"
        + "21sZYrjFV+bs583tbSIMYAapk8jSKtk+r1z48KQdsR9czydmy2yYbdXruXMBPdQrf+11BB\n"
        + "dCs1E9iFet1UB8OruVeduD5dm0In7yJK1Qo18xe0NpOjOHeZ1ixAxdOt9zuolAlBTwZYth\n"
        + "FMESME8AAAEQApLNRAKSzUQAAAATZWNkc2Etc2hhMi1uaXN0cDUyMQAAAAhuaXN0cDUyMQ\n"
        + "AAAIUEAPdAJ+XsbJd1BFNHfH4alfK4JqMsydtbGWK4xVfm7OfN7W0iDGAGqZPI0irZPq9c\n"
        + "+PCkHbEfXM8nZstsmG3V67lzAT3UK3/tdQQXQrNRPYhXrdVAfDq7lXnbg+XZtCJ+8iStUK\n"
        + "NfMXtDaTozh3mdYsQMXTrfc7qJQJQU8GWLYRTBEjBPAAAAQgFHl5a1JDqcCeaAx84z3u/v\n"
        + "z7dyVl4uohlQPaiZ+hhtbbUg6oLMnVGGjjmviR0C0aDzx0xDEsK8TseFd16mBWpOnAAAAA\n"
        + "5tYXJrQGJhcm5hY2xlcwECAwQ=\n"
        + "-----END OPENSSH PRIVATE KEY-----\n";

    public static void main(
        String[] args)
    {
        runTest(new OpenSSHKeyParsingTests());
    }


    public void testDSA()
        throws Exception
    {
        CipherParameters pubSpec = OpenSSHPublicKeyUtil.parsePublicKey(Base64.decode("AAAAB3NzaC1kc3MAAACBAJBB5+S4kZZYZLswaQ/zm3GM7YWmHsumwo/Xxu+z6Cg2l5PUoiBBZ4ET9EhhQuL2ja/zrCMCi0ZwiSRuSp36ayPrHLbNJb3VdOuJg8xExRa6F3YfVZfcTPUEKh6FU72fI31HrQmi4rpyHnWxL/iDX496ZG2Hdq6UkPISQpQwj4TtAAAAFQCP9TXcVahR/2rpfEhvdXR0PfhbRwAAAIBdXzAVqoOtb9zog6lNF1cGS1S06W9W/clvuwq2xF1s3bkoI/xUbFSc0IAPsGl2kcB61PAZqcop50lgpvYzt8cq/tbqz3ypq1dCQ0xdmJHj975QsRFax+w6xQ0kgpBhwcS2EOizKb+C+tRzndGpcDSoSMuVXp9i4wn5pJSTZxAYFQAAAIEAhQZc687zYxrEDR/1q6m4hw5GFxuVvLsC+bSHtMF0c11Qy4IPg7mBeP7K5Kq4WyJPtmZhuc5Bb12bJQR6qgd1uLn692fe1UK2kM6eWXBzhlzZ54BslfSKHGNN4qH+ln3Zaf/4rpKE7fvoinkrgkOZmj0PMx9D6wlpHKkXMUxeXtc="));

        CipherParameters privSpec = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(new PemReader(new StringReader("-----BEGIN DSA PRIVATE KEY-----\n" +
            "MIIBuwIBAAKBgQCQQefkuJGWWGS7MGkP85txjO2Fph7LpsKP18bvs+goNpeT1KIg\n" +
            "QWeBE/RIYULi9o2v86wjAotGcIkkbkqd+msj6xy2zSW91XTriYPMRMUWuhd2H1WX\n" +
            "3Ez1BCoehVO9nyN9R60JouK6ch51sS/4g1+PemRth3aulJDyEkKUMI+E7QIVAI/1\n" +
            "NdxVqFH/aul8SG91dHQ9+FtHAoGAXV8wFaqDrW/c6IOpTRdXBktUtOlvVv3Jb7sK\n" +
            "tsRdbN25KCP8VGxUnNCAD7BpdpHAetTwGanKKedJYKb2M7fHKv7W6s98qatXQkNM\n" +
            "XZiR4/e+ULERWsfsOsUNJIKQYcHEthDosym/gvrUc53RqXA0qEjLlV6fYuMJ+aSU\n" +
            "k2cQGBUCgYEAhQZc687zYxrEDR/1q6m4hw5GFxuVvLsC+bSHtMF0c11Qy4IPg7mB\n" +
            "eP7K5Kq4WyJPtmZhuc5Bb12bJQR6qgd1uLn692fe1UK2kM6eWXBzhlzZ54BslfSK\n" +
            "HGNN4qH+ln3Zaf/4rpKE7fvoinkrgkOZmj0PMx9D6wlpHKkXMUxeXtcCFELnLOJ8\n" +
            "D0akSCUFY/iDLo/KnOIH\n" +
            "-----END DSA PRIVATE KEY-----\n")).readPemObject().getContent());

        DSASigner signer = new DSASigner();
        signer.init(true, privSpec);

        byte[] originalMessage = new byte[10];
        secureRandom.nextBytes(originalMessage);

        BigInteger[] rs = signer.generateSignature(originalMessage);

        signer.init(false, pubSpec);

        isTrue("DSA test", signer.verifySignature(originalMessage, rs[0], rs[1]));

    }


    public void testECDSA_curvesFromSSHKeyGen()
        throws Exception
    {

        String[][] pairs = new String[][]{
            {
                "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBbxKE+/DXstQZmwH7Wso8SUt8LvYoMQpxN/7INC0lMn7mNCbxJcSOCfucBuWOrdoFyFZUkGli2mzKj3hJlcPiI=",
                "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
                    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS\n" +
                    "1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQQW8ShPvw17LUGZsB+1rKPElLfC72KD\n" +
                    "EKcTf+yDQtJTJ+5jQm8SXEjgn7nAbljq3aBchWVJBpYtpsyo94SZXD4iAAAAuKFclDShXJ\n" +
                    "Q0AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBbxKE+/DXstQZmw\n" +
                    "H7Wso8SUt8LvYoMQpxN/7INC0lMn7mNCbxJcSOCfucBuWOrdoFyFZUkGli2mzKj3hJlcPi\n" +
                    "IAAAAhAP4L/ciGBDF4HoQSvMaKM8svW4Ss0uYi7HkZ1sn/zCe0AAAAHW1lZ2Fud29vZHNA\n" +
                    "dHljaGUtMzI2NS5nYXRld2F5AQI=\n" +
                    "-----END OPENSSH PRIVATE KEY-----\n"
            },
            {
                "AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBOT0Cc/zauJsOWo/0P0sMNeyFI5Enz3+lKJtjWXQD7DpFgZmG5Ise8IXR5/ot7fo0kWlYQrye/uSmNmWBuDvOpBCHOnyR6Kaej36qoOO/gwbH+mezSYXSxCTA9Qb8VzxLA==",
                "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
                    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAiAAAABNlY2RzYS\n" +
                    "1zaGEyLW5pc3RwMzg0AAAACG5pc3RwMzg0AAAAYQTk9AnP82ribDlqP9D9LDDXshSORJ89\n" +
                    "/pSibY1l0A+w6RYGZhuSLHvCF0ef6Le36NJFpWEK8nv7kpjZlgbg7zqQQhzp8keimno9+q\n" +
                    "qDjv4MGx/pns0mF0sQkwPUG/Fc8SwAAADorZ3naK2d52gAAAATZWNkc2Etc2hhMi1uaXN0\n" +
                    "cDM4NAAAAAhuaXN0cDM4NAAAAGEE5PQJz/Nq4mw5aj/Q/Sww17IUjkSfPf6Uom2NZdAPsO\n" +
                    "kWBmYbkix7whdHn+i3t+jSRaVhCvJ7+5KY2ZYG4O86kEIc6fJHopp6Pfqqg47+DBsf6Z7N\n" +
                    "JhdLEJMD1BvxXPEsAAAAMQDLno+rINnY7/Ht1WmSGZYJ3EMPtysbxuBnQFEL4USa3kyAb1\n" +
                    "QMR6+jtqraKtE7kLwAAAAdbWVnYW53b29kc0B0eWNoZS0zMjY1LmdhdGV3YXkBAg==\n" +
                    "-----END OPENSSH PRIVATE KEY-----\n"
            },
            {
                "AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBADXE/q1WSR002vRI+tiPLpdRjzeymSk+RjD7ZIC9CndqLmI0rhTMh5xReAzved12BH9lQJIGIw4YoIQDudsMbRUsQEjFvbFzSXLJBYWdZf8Voa/97/R9w/i8bKUMUPP0disypZlGdQn5+XvzHG6bhX2Qr9aJacGFZoVHugF/M8QyC+GyA==",
                "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
                    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAArAAAABNlY2RzYS\n" +
                    "1zaGEyLW5pc3RwNTIxAAAACG5pc3RwNTIxAAAAhQQA1xP6tVkkdNNr0SPrYjy6XUY83spk\n" +
                    "pPkYw+2SAvQp3ai5iNK4UzIecUXgM73nddgR/ZUCSBiMOGKCEA7nbDG0VLEBIxb2xc0lyy\n" +
                    "QWFnWX/FaGv/e/0fcP4vGylDFDz9HYrMqWZRnUJ+fl78xxum4V9kK/WiWnBhWaFR7oBfzP\n" +
                    "EMgvhsgAAAEgs+rbdbPq23UAAAATZWNkc2Etc2hhMi1uaXN0cDUyMQAAAAhuaXN0cDUyMQ\n" +
                    "AAAIUEANcT+rVZJHTTa9Ej62I8ul1GPN7KZKT5GMPtkgL0Kd2ouYjSuFMyHnFF4DO953XY\n" +
                    "Ef2VAkgYjDhighAO52wxtFSxASMW9sXNJcskFhZ1l/xWhr/3v9H3D+LxspQxQ8/R2KzKlm\n" +
                    "UZ1Cfn5e/McbpuFfZCv1olpwYVmhUe6AX8zxDIL4bIAAAAQgCM8ojULpNk3UhBZhPfK+Tw\n" +
                    "QjT9MHU0OTi4twvKPAE0vOLQ/C1g9AMlspyKxS2NKx2gxxXISowFGNL6Jkx9198ElQAAAB\n" +
                    "1tZWdhbndvb2RzQHR5Y2hlLTMyNjUuZ2F0ZXdheQECAwQF\n" +
                    "-----END OPENSSH PRIVATE KEY-----\n"
            }
        };

        String[] ecPriv = new String[] { ecdsa256Key, ecdsa384Key, ecdsa521Key };
        for (int i = 0; i != ecPriv.length; i++)
        {
            ECPrivateKeyParameters privKey = (ECPrivateKeyParameters)OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(
                new PemReader(
                    new StringReader(ecPriv[i])).readPemObject().getContent());
            ECPoint q = privKey.getParameters().getG().multiply(privKey.getD());

            doECSigTest(new ECPublicKeyParameters(q, privKey.getParameters()), privKey);
        }

        for (int i = 0; i != pairs.length; i++)
        {
            String[] pair = pairs[i];

            CipherParameters pubSpec = OpenSSHPublicKeyUtil.parsePublicKey(
                Base64.decode(pair[0]));

            CipherParameters privSpec = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(
                new PemReader(
                    new StringReader(pair[1])).readPemObject().getContent());

            doECSigTest(pubSpec, privSpec);

            ECDSASigner signer;
            byte[] originalMessage;
            BigInteger[] rs;

            //
            // Test encode
            //


            CipherParameters recoveredPubKey = OpenSSHPublicKeyUtil.parsePublicKey(OpenSSHPublicKeyUtil.encodePublicKey((AsymmetricKeyParameter)pubSpec));
            CipherParameters recoveredPrivateKey = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(OpenSSHPrivateKeyUtil.encodePrivateKey((AsymmetricKeyParameter)privSpec));

            signer = new ECDSASigner();
            signer.init(true, privSpec);

            originalMessage = new byte[10];
            secureRandom.nextBytes(originalMessage);

            rs = signer.generateSignature(originalMessage);

            signer.init(false, pubSpec);

            isTrue("ECDSA test post encoded / decode", signer.verifySignature(originalMessage, rs[0], rs[1]));
        }

    }

    private void testFido2Keys()
    {
        // P-256 ECDSA Key
        byte[] decode = Base64.decode("AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBPnfX2RzzEvD5CEX/0G3LLXrDWjrir9jZ2omSoxNyNT44cSiOP2v/WodnYpQdJsLIZn5bGNI0UxzxTuFzdizrWkAAAAEc3NoOg==");

        CipherParameters xpubSpec = OpenSSHPublicKeyUtil.parsePublicKey(decode);
    }

    private void doECSigTest(CipherParameters pubSpec, CipherParameters privSpec)
    {
        ECDSASigner signer = new ECDSASigner();
        signer.init(true, privSpec);

        byte[] originalMessage = new byte[10];
        secureRandom.nextBytes(originalMessage);

        BigInteger[] rs = signer.generateSignature(originalMessage);

        signer.init(false, pubSpec);

        isTrue("ECDSA test", signer.verifySignature(originalMessage, rs[0], rs[1]));
    }


    public void testECDSA()
        throws Exception
    {
        CipherParameters pubSpec = OpenSSHPublicKeyUtil.parsePublicKey(Base64.decode("AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHq5qxGqnh93Gpbj2w1Avx1UwBl6z5bZC3Viog1yNHDZYcV6Da4YQ3i0/hN7xY7sUy9dNF6g16tJSYXQQ4tvO3g="));

        CipherParameters privSpec = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(new PemReader(new StringReader("-----BEGIN EC PRIVATE KEY-----\n" +
            "MHcCAQEEIHeg/+m02j6nr4bO8ubfbzhs0fqOjiuIoWbvGnVg+FmpoAoGCCqGSM49\n" +
            "AwEHoUQDQgAEermrEaqeH3caluPbDUC/HVTAGXrPltkLdWKiDXI0cNlhxXoNrhhD\n" +
            "eLT+E3vFjuxTL100XqDXq0lJhdBDi287eA==\n" +
            "-----END EC PRIVATE KEY-----\n")).readPemObject().getContent());

        doECSigTest(pubSpec, privSpec);

    }


    public void testED25519()
        throws Exception
    {

        CipherParameters pubSpec = OpenSSHPublicKeyUtil.parsePublicKey(Base64.decode("AAAAC3NzaC1lZDI1NTE5AAAAIM4CaV7WQcy0lht0hclgXf4Olyvzvv2fnUvQ3J8IYsWF"));

        CipherParameters privSpec = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(new PemReader(new StringReader("-----BEGIN OPENSSH PRIVATE KEY-----\n" +
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n" +
            "QyNTUxOQAAACDOAmle1kHMtJYbdIXJYF3+Dpcr8779n51L0NyfCGLFhQAAAKBTr4PvU6+D\n" +
            "7wAAAAtzc2gtZWQyNTUxOQAAACDOAmle1kHMtJYbdIXJYF3+Dpcr8779n51L0NyfCGLFhQ\n" +
            "AAAED4BTHeR3YD7CFQqusztfL5K+YSD4mRGLBwb7jHiXxIJM4CaV7WQcy0lht0hclgXf4O\n" +
            "lyvzvv2fnUvQ3J8IYsWFAAAAG21lZ2Fud29vZHNAdHljaGUtMzI2NS5sb2NhbAEC\n" +
            "-----END OPENSSH PRIVATE KEY-----\n")).readPemObject().getContent());

        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, privSpec);

        byte[] originalMessage = new byte[10];
        secureRandom.nextBytes(originalMessage);
        signer.update(originalMessage, 0, originalMessage.length);

        byte[] sig = signer.generateSignature();

        signer.init(false, pubSpec);

        signer.update(originalMessage, 0, originalMessage.length);


        isTrue("ED25519Signer test", signer.verifySignature(sig));

    }


    public void testFailures()
        throws Exception
    {
        byte[] blob = new PemReader(new StringReader("-----BEGIN OPENSSH PRIVATE KEY-----\n" +
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n" +
            "QyNTUxOQAAACDOAmle1kHMtJYbdIXJYF3+Dpcr8779n51L0NyfCGLFhQAAAKBTr4PvU6+D\n" +
            "7wAAAAtzc2gtZWQyNTUxOQAAACDOAmle1kHMtJYbdIXJYF3+Dpcr8779n51L0NyfCGLFhQ\n" +
            "AAAED4BTHeR3YD7CFQqusztfL5K+YSD4mRGLBwb7jHiXxIJM4CaV7WQcy0lht0hclgXf4O\n" +
            "lyvzvv2fnUvQ3J8IYsWFAAAAG21lZ2Fud29vZHNAdHljaGUtMzI2NS5sb2NhbAEC\n" +
            "-----END OPENSSH PRIVATE KEY-----\n")).readPemObject().getContent();


        //
        // Altering the check value.
        //

        blob[98] ^= 1;

        try
        {
            CipherParameters privSpec = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(blob);
            fail("Change should trigger failure.");
        }
        catch (IllegalStateException iles)
        {
            isEquals("Check value mismatch ", iles.getMessage(), "private key check values are not the same");
        }


        //
        // Altering the cipher name.
        //


        blob = new PemReader(new StringReader("-----BEGIN OPENSSH PRIVATE KEY-----\n" +
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n" +
            "QyNTUxOQAAACDOAmle1kHMtJYbdIXJYF3+Dpcr8779n51L0NyfCGLFhQAAAKBTr4PvU6+D\n" +
            "7wAAAAtzc2gtZWQyNTUxOQAAACDOAmle1kHMtJYbdIXJYF3+Dpcr8779n51L0NyfCGLFhQ\n" +
            "AAAED4BTHeR3YD7CFQqusztfL5K+YSD4mRGLBwb7jHiXxIJM4CaV7WQcy0lht0hclgXf4O\n" +
            "lyvzvv2fnUvQ3J8IYsWFAAAAG21lZ2Fud29vZHNAdHljaGUtMzI2NS5sb2NhbAEC\n" +
            "-----END OPENSSH PRIVATE KEY-----\n")).readPemObject().getContent();


        blob[19] = (byte)'C';

        try
        {
            CipherParameters privSpec = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(blob);
            fail("Change should trigger failure.");
        }
        catch (IllegalStateException iles)
        {
            isEquals("passphrase required ", iles.getMessage(), "passphrase required to decrypt encrypted OpenSSH private key");
        }

        //
        // A uint32 length-prefix with bit 31 set decodes to a negative Java int. Such a
        // length is never producible by a conforming SSH encoder, but a malformed key can
        // carry one; it must be rejected with the same "not enough data" diagnostic as the
        // over-large case, not corrupt the parse position or surface a cryptic copyOfRange
        // message. Exercises the readBlock and readBigNumPositive guards via the public
        // OpenSSHPublicKeyUtil.parsePublicKey path.
        //

        // First length field (the key-type name, read via readBlock) is 0xFFFFFFFF.
        byte[] negNameLen = new byte[]{ (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF };

        try
        {
            OpenSSHPublicKeyUtil.parsePublicKey(negNameLen);
            fail("negative block length should trigger failure.");
        }
        catch (IllegalArgumentException iae)
        {
            isEquals("negative block length ", iae.getMessage(), "not enough data for block");
        }

        // "ssh-rsa" name, then a big-num exponent length of 0xFFFFFFFF (negative int).
        byte[] sshRsa = Strings.toByteArray("ssh-rsa");
        byte[] negBigNum = new byte[4 + sshRsa.length + 4];
        negBigNum[0] = 0;
        negBigNum[1] = 0;
        negBigNum[2] = 0;
        negBigNum[3] = (byte)sshRsa.length;
        System.arraycopy(sshRsa, 0, negBigNum, 4, sshRsa.length);
        for (int i = 4 + sshRsa.length; i < negBigNum.length; i++)
        {
            negBigNum[i] = (byte)0xFF;
        }

        try
        {
            OpenSSHPublicKeyUtil.parsePublicKey(negBigNum);
            fail("negative big-num length should trigger failure.");
        }
        catch (IllegalArgumentException iae)
        {
            isEquals("negative big-num length ", iae.getMessage(), "not enough data for big num");
        }
    }

    /**
     * github #1733 - decryption of passphrase-protected openssh-key-v1 keys across the
     * OpenSSH cipher suite (bcrypt KDF). The keys below were produced by ssh-keygen with
     * passphrase "Test1234!"; each expected value is the deterministic key material
     * (ed25519 32-byte seed||public, RSA modulus, or EC private scalar, in hex).
     */
    public void testEncryptedKeys()
        throws Exception
    {
        checkEncryptedKey("aes256-ctr",
            "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
            "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABD4XaoKXH\n" +
            "N9dMM5dz+nRBC6AAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIHs3/Bh5SIn8aexd\n" +
            "42KtdGV83J4+sckvemTmsG0u6uOyAAAAkBLLK8FUZ0ErL2dC/3fDEz+MdA6MMVZv0Q83OJ\n" +
            "5AbQ0WvN0wLo6lARyiiZm2L4Z3rO5XGkY+BpDrNUI1iKNd39VdgyBLX+u0dbJ/EI5ZXMYs\n" +
            "j5iVU+CD0fJc7KrToTDvblDoS3jeW9yXrLdnV5Mi25gdQLojq8x3px2Dv+HoqT3vTuAivl\n" +
            "ISNUnmozjANHauJg==\n" +
            "-----END OPENSSH PRIVATE KEY-----\n",
            "0ad120d52190b5a6edf251e51e9eedf70acc46b3643d72c9ae952021afc1af68");

        checkEncryptedKey("aes128-ctr",
            "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
            "b3BlbnNzaC1rZXktdjEAAAAACmFlczEyOC1jdHIAAAAGYmNyeXB0AAAAGAAAABD65HXuos\n" +
            "80kHc6jA6zQyjpAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIBfVtOvwgqyb+PmG\n" +
            "qUgKEuQ22VVe/BRgY0psSvfWPn+UAAAAkGD9cseM/xe9hi2/hi1A7RkLmSGZ35MuK3q091\n" +
            "TeerghU8asugJkKVpx40CNnYcjWWvdQPDd3UxJY4TPhHrReShEw/jCHddY2EKkX+DaB4Vg\n" +
            "ov37XQ1vG5chvGsHzbCtGB6+zR+MBSBqpAV7gk61NJpI0gKEQ4Rw0X7z6KFSNcYObyqJ/I\n" +
            "QWinajEzSw00J1DA==\n" +
            "-----END OPENSSH PRIVATE KEY-----\n",
            "ef7918190fd8f3497010cc0db19468aedc89f3cc728216a7a7663e66e07c20bc");

        checkEncryptedKey("aes192-ctr",
            "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
            "b3BlbnNzaC1rZXktdjEAAAAACmFlczE5Mi1jdHIAAAAGYmNyeXB0AAAAGAAAABBcwtTCKS\n" +
            "P9X1AVv/6upTd2AAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIAxrhqEQOiXfopRa\n" +
            "h4A3uTJRFcHpvah0FwqTmulJ2UjMAAAAkGrpJJBHf2tI1RKH7ZnWFjl5AdlMaFXM3U2KYq\n" +
            "YMiKHTC+i85zBWN90LXp13kjxuz11S3M3NCqh0uYE7j6CRf7tC3LaUDnaqFoN0pP+S3ypK\n" +
            "i8WGMx3VANB0AuyzGRF99guDlP1yTq/stcf41ggKZ40JujdhCoklj6EzvUCLF3WknGTWtj\n" +
            "ElAcS55uL1DfLPxQ==\n" +
            "-----END OPENSSH PRIVATE KEY-----\n",
            "8dc8b9b50506b43e71cbdd5887b2f0a1d1c59d512aa3f1f0e44f0a0cdbf0d56b");

        checkEncryptedKey("aes256-cbc",
            "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
            "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jYmMAAAAGYmNyeXB0AAAAGAAAABBUK0hoIh\n" +
            "NVvdqYYjVNHzO8AAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIBR52tLLhGaQVYg8\n" +
            "61k+6hM8Ck7arTmAlhEzZpXQkBtHAAAAkDqBF9pv30NX6YrOEJMYupzi9eR6jdhw7502Wq\n" +
            "0OnL445d5oB32RpxiGlQ8onN0ZZY6wjV4al8C81kpTLu/ECD0qcLm/zo/CeKMBNFv7K+AV\n" +
            "ytMzmBy/ajdxn2fDdJqUgHRDyCD+rMbcc3y1WB5F5ONji00+M1MQa7qZjRsWO4AOd3yXGw\n" +
            "Drnpu9rs8Wz/W8NA==\n" +
            "-----END OPENSSH PRIVATE KEY-----\n",
            "925820043002fb0e96b82ea775501cd2da9eb61a71383e5ab09c7bf7e8ff31b4");

        checkEncryptedKey("aes128-cbc",
            "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
            "b3BlbnNzaC1rZXktdjEAAAAACmFlczEyOC1jYmMAAAAGYmNyeXB0AAAAGAAAABB7OnTR7J\n" +
            "aVNVY9Zs8FhKZUAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIExC0pZHM66wbsIh\n" +
            "yyQpzSy+OF5AcoCf/NMrtGmwqCJdAAAAkDfsRluSpZ5r82JzjvPU0+AdknAn++kXD8vfb1\n" +
            "CHz3C9VHWmTtFlkkgSUwzCf2mW6Ev0M+gX8XRQHst6+tNqUnLJLdNGNoGKD7PW+k8ZXE8j\n" +
            "cJx6WdTcJHqm343diQ7EfZLwe/inrC6pKrl/+OkU4ao5eUdc7ftsqWvTh4F7dcIq/tgSmp\n" +
            "ZXPPUZtj5zfvoZxQ==\n" +
            "-----END OPENSSH PRIVATE KEY-----\n",
            "d8933d873bf493d3bf4d03170c1730762f2fd2c61444df164e302dfc2c312f8f");

        checkEncryptedKey("3des-cbc",
            "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
            "b3BlbnNzaC1rZXktdjEAAAAACDNkZXMtY2JjAAAABmJjcnlwdAAAABgAAAAQOpEywjI8Qn\n" +
            "w3w7BPeV1ScwAAABAAAAABAAAAMwAAAAtzc2gtZWQyNTUxOQAAACDxoqNYLcC0DTKb76mN\n" +
            "k8sVXtyx8lrr6CVoQW52nVi+EAAAAJArCdk43AjdgrltLKUx1JrTSSRX4c7JWfZJ4ofTgR\n" +
            "2QwoglwyBSNT3huXOJFMNnloeSNa3EEGAvZS/NScPSC0B2V+o+dknbLmaJSKISRmxiLoZc\n" +
            "9xCWuEysuWBLDP16a8GuDC2SrJWPy2V4YZ+AG2Pg4hi31PV/PyufaK2d8BmZTu9YmuPer9\n" +
            "qItCt3uY39/NE=\n" +
            "-----END OPENSSH PRIVATE KEY-----\n",
            "7879e37e8803109c7db26729394172b17649c0b0cdaaa83eff91be532a49b7bb");

        checkEncryptedKey("aes256-gcm@openssh.com",
            "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
            "b3BlbnNzaC1rZXktdjEAAAAAFmFlczI1Ni1nY21Ab3BlbnNzaC5jb20AAAAGYmNyeXB0AA\n" +
            "AAGAAAABA6fSk3ItHVNeQXXxrdBT6VAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAA\n" +
            "INuBZXiaJuwfDT80owG0HJR21ztvk+dnblKrN91Y0QDfAAAAkDKV/baBadVkqyyygAe4Ya\n" +
            "RY6wEp7Y05j3hQV7qSGl3vLDZ2YRzafhdcECWL5qDThKeFizMmnqAoGnidrEC/bzu4VyQ/\n" +
            "8bkJhu3sqM5dVFAFBsfv38SkZVP/vsaU61lhAtpbt9J6M1i5vGonnHWLxV0aT6iOdIkzLu\n" +
            "UhUjm5+8v/gQ16/4+5AqlK2ltKYRXGJHepmBevQGiEdsAdTtt6En4=\n" +
            "-----END OPENSSH PRIVATE KEY-----\n",
            "c1f5bc9f64983c1507be7a1372d873e56eb959c0fc31f48c97d93207e6965210");

        checkEncryptedKey("aes128-gcm@openssh.com",
            "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
            "b3BlbnNzaC1rZXktdjEAAAAAFmFlczEyOC1nY21Ab3BlbnNzaC5jb20AAAAGYmNyeXB0AA\n" +
            "AAGAAAABBx775z1G1CHFmOttl4UcFHAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAA\n" +
            "IHHDo+8swumF2dza5gsYzJFtnCOXOEEzLQqnqFjlOcfJAAAAkM+rf2z1eNDN2eu9RosxhL\n" +
            "HNtpb1SEPmBFNEiEl+aIJad9D6V2uZIucKtEqSyTDV4sYMEktCejt3njxYwa20P2FMUAF7\n" +
            "OFnxqekBD19hHg6oN4odqnphtQAiKWqlK5DETKgcgiQIuayIyw0UdkcWccjy9fJYouh3ga\n" +
            "KKfBAyQS8fQwZxxmOs6y8ZmKgkriw864tX0O8sH4437nduK4B4690=\n" +
            "-----END OPENSSH PRIVATE KEY-----\n",
            "74a2baaedd54a6ffb87ec2fb729b4012e14cc9c7d9a197606ca503e4770ed0e4");

        checkEncryptedKey("chacha20-poly1305@openssh.com",
            "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
            "b3BlbnNzaC1rZXktdjEAAAAAHWNoYWNoYTIwLXBvbHkxMzA1QG9wZW5zc2guY29tAAAABm\n" +
            "JjcnlwdAAAABgAAAAQZeYt3vUlx5onMOCJPTNChAAAABAAAAABAAAAMwAAAAtzc2gtZWQy\n" +
            "NTUxOQAAACCNHqOGdurGrXq0zzzNz8hhu5QwbFCbD8Mn08fkgchuMwAAAJA33h9WYKCfi7\n" +
            "P9P6CEKd5Ha5hAdYi9ZKgTffR7WMfu+eBM756dV1ljwYL+FH1ZmkTei2o4yjRxa7Ek5UGV\n" +
            "DJQQAmNNfNFk5AQsEcSVUZ7JuG41yeT449ujFWv9v5pk/dtVzhcuUeXDvUxrCOQzE94oBK\n" +
            "g1mg3jkd1Ahb3rcPp8988lutsBg1TIRhqDGkmymRKzOEpuGU2pqfKp9048jcex\n" +
            "-----END OPENSSH PRIVATE KEY-----\n",
            "5505052cf395cbe63dbe0437a755b55c4efb1406d915c135411066208625bc8a");

        checkEncryptedKey("aes256-ctr",
            "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
            "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABB50uPQMn\n" +
            "4vfG13Q/m8WTS4AAAAEAAAAAEAAAGXAAAAB3NzaC1yc2EAAAADAQABAAABgQDGk5mXBFuM\n" +
            "g6cboE6mLjpSoLaRI6uzQZVVqCNpR6zHokDCDBA+LssA25NGlW2ZKyCVgXB9rZwahkfSXM\n" +
            "RTI5/M3/7wldtZgyS2PNBHnRbK2ujQnzwExYdDIen4mbZOuRwlAPVbhXGQ1HNmwsssvBhq\n" +
            "VQ+aKAP3ro+ca0mu2e9DVcImecEaP9zwpLmfwnqBqOvJDI/PMHWJ/CUGqXvqaHwKWJbXmh\n" +
            "sP+kppISVRwNvCO280nFnEB2L/Sg1g2IJhy+Q9Rj3XjtqQVDHivN1GcRXpl9sAgt2kKDdi\n" +
            "KRKAOAGeAa+3GogS50yHLRx7xBhCFDC+SQX92/RmiCRPe6haaj2DWiu5GlzYuWyElYJb4A\n" +
            "u4P7EmFJxgnIklbA1VZfOJIgzpS8zH9RCcZHUXYgie4MwdhXB9svoXldkkjistoPEQa0Zy\n" +
            "NoCTuAISpa5EHR6ymrXUUXhv2JWC+G7oOJU01gUr8SzewLQvar0kWZTAbQfXor9C1VoQdd\n" +
            "tiONdvp1MSWYsAAAWAB9EiEahx1wV56fp41BscViRYPuEFrmO9/gdqVab/aOTTAOobfgOb\n" +
            "wqlZkxeEpA75yU817EmMS+fvd1tJyNUXMxY6Zc5qn1eQ5+lw8jaol489D8cKsS55h551XZ\n" +
            "iKgNVbP0YR9nYzgNiBVXORm+UZVNXnRyn35xRAz0Sw/5lMbYk4J0PpUZyscTS5Zwz46cRb\n" +
            "MnquLg2yZvJFbddOayGLdmJzXT542jkNj1pveRL2fiK7/ALozOSwhLe1ZWaYolrjWi7bHm\n" +
            "IiBAFKQbLlkJeYgm+3TDQo+LAw02dkC2rDcmFk4svWFXfPmaWggPKd/BKqwTlx0JkhwboY\n" +
            "G+6z8PKrr28OPO7NrBbzkR7hfIk3qizYGNJ88vpjrz8FxHIIUyRm5Lokj/zDszRuYDtUjb\n" +
            "xC62zSsnY4yvZLjDJaaBYznGi4gJWHfTcoYm/7sY29vbPqF3YSyXktw51DE4AdF52LONmy\n" +
            "ThZQ58jKvRY4rLr8aW1W2wFCLzQhUb2HDnB8cViTH4j2We/QQrRUj8/VIcIIT+/tS7sIo/\n" +
            "beFhQXJLipBWRtATaclRcvr7b2h8imHR5vq1mebLwHM/97kC5dwVjJ5/nXfFNEa4GdW+dI\n" +
            "y1dGNk2LrEfaT8PkaalZ09kC56Hrje1hgnZAgV3uheIDq6ijODdzxNRxXBXf16ljqFoug5\n" +
            "Qg4xVp7yJTEs3II+eHRetAi/OTybf4AuF3V32dG9Cr+1QJ9WETFG60F8Ttud2+STPqlzlR\n" +
            "EkkuqQG/8TP2STFXj5DjGui0A1+o7KWm3zuP/0KTbOuOp2nVNqUuaSDnEn2zU58//jQFJR\n" +
            "iu2Y58SdM3aCWnCRUYfvbe6OJ/sfwoeD/J9N1E/C0aDWgYuWP/d38yek1ELoLlpKtrz+8P\n" +
            "ajN5rxUlnDeU+Z8HcIbl8xA/toXb4zvVVRc17pF4ELeoT2c5OQI7WBypuNgei/Z5Iekl+N\n" +
            "oV3Rt2lvd09MVzPwWvPCKONDhObRv7AEKwDc7UsK5+nt1ww1XLswMuN9JGs10Zdq5VU6lp\n" +
            "97WNgH/sX5XEZaXCjHVJvBmmCYd0Wh3k7YwTOkxVGSy1nhC5R8g7UlPzWxOwYwEk1SmW8o\n" +
            "OtpJs9oSycp5TaXTzF82a9hA1Mjun7kpZnee0hnir2cLRp+1rzCWBs/ABJITuLw9kOPKxu\n" +
            "5IVC0vd2WMAFM0eF59FCP6OGQid28edLmVZ/uK7uY483gM9RPmDF1mTDbL2w2U6zP954Lz\n" +
            "tmPPZK1yD6+d58CxzW0pzQuxebiF/eeuvDjneqqOAErdR7/vA9HUjqa4owFStERPtja3Qn\n" +
            "kwDQzhiScSIp1h87ok7ozVnOipF6EtjFOXlD1nPw685fgDgFGpMq5xdBmTbiqVKWbJxRTY\n" +
            "MdS4c6lH9ksG+Dcm0Gpv1957hHIfviaRsXba33lPfpBki23xL7CkMFWCpzG2VdZWK9Y3XY\n" +
            "xRqtwQ1E31MeMrnrQAJSxe64iHU2dRW5w/mpYIrO2CKaQzsiN4t1wOodHzyuzXoAFp3fSY\n" +
            "IELkl27ggHEBlnMLpP1wSibqfqNADQtu3MFABQh2nen0Lec9YuqpH/hFl6eqpchbJiWkun\n" +
            "vpaCL6eTO2kIZvNU8YjAreej5CXl6tnX+wiVc9A+ROOIcMk+ui8ESPvSue7NS/DRk4Wxf4\n" +
            "FRABBcXjSsKOOl6jZOjwWUwY6Fp+WQQtmjUJOfiMrrsjN8mGxLuYpJtzLeZj1AriHdrj2K\n" +
            "L05RwtWfl9R2dHwjQo6AuzD8XgSj4njqNHdn6S0AKkVjopil7o2bav2VTpbsCwIc+qU4I6\n" +
            "PmBtd+iRWbotbgsFO6e8jaYNPd+8g4uiqLWAb41vLW2rq8fuyV1EhwaUuFQMqQrcbhq8gL\n" +
            "0CFPzw==\n" +
            "-----END OPENSSH PRIVATE KEY-----\n",
            "c6939997045b8c83a71ba04ea62e3a52a0b69123abb3419555a8236947acc7a240c20c103e2ecb00db9346956d992b209581707dad9c1a8647d25cc453239fccdffef095db598324b63cd0479d16cadae8d09f3c04c5874321e9f899b64eb91c2500f55b857190d47366c2cb2cbc186a550f9a2803f7ae8f9c6b49aed9ef4355c22679c11a3fdcf0a4b99fc27a81a8ebc90c8fcf307589fc2506a97bea687c0a5896d79a1b0ffa4a69212551c0dbc23b6f349c59c40762ff4a0d60d88261cbe43d463dd78eda905431e2bcdd467115e997db0082dda428376229128038019e01afb71a8812e74c872d1c7bc418421430be4905fddbf46688244f7ba85a6a3d835a2bb91a5cd8b96c8495825be00bb83fb126149c609c89256c0d5565f389220ce94bccc7f5109c64751762089ee0cc1d85707db2fa1795d9248e2b2da0f1106b4672368093b80212a5ae441d1eb29ab5d451786fd89582f86ee8389534d6052bf12cdec0b42f6abd245994c06d07d7a2bf42d55a1075db6238d76fa75312598b");

        checkEncryptedKey("aes256-ctr",
            "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
            "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDfFJi65K\n" +
            "f09iHP5l5Jg6TzAAAAEAAAAAEAAABoAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlz\n" +
            "dHAyNTYAAABBBKzN/6RkvOl5Eo72vr7gCGPjh1mW5R2t8G7YGyCDGhsgnUdRYW/zwPZAqu\n" +
            "tkZsk6Ytf007s8M0jLMYiwhMM0o18AAACgDhq9mvCR6ZoRXSnD7+VWKmZ0pU4U9V3+4OVb\n" +
            "jEDgFj3CqYw6jUPkgF5qt4UTrzMRGWGyaEFNxXnHTYr9Qeqf3xnr+BHjPpvUUYXcUOS4AC\n" +
            "yYCd39Dg13PGl7jHRT4gd9VVGg0WR7/q6/kbe4qPYiaYNzbzKusVipo4wtvPqaMotRMyyR\n" +
            "Mh0LzQlrCw1m+OcuTv+PhWMkqY/RTGzZfvqbZA==\n" +
            "-----END OPENSSH PRIVATE KEY-----\n",
            "ef07ad1bbb71aaaf49536840adce11a16ee7ebfbcd2f2a48f84a6638309031f9");

    }

    private void checkEncryptedKey(String cipher, String pem, String expectedHex)
        throws Exception
    {
        byte[] blob = new PemReader(new StringReader(pem)).readPemObject().getContent();

        AsymmetricKeyParameter key = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(blob, Strings.toByteArray("Test1234!"));

        isEquals("decrypted key material for " + cipher, expectedHex, keyMaterial(key));

        // a wrong passphrase must be rejected, not silently mis-decrypted
        try
        {
            OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(blob, Strings.toByteArray("definitely-wrong"));
            fail("wrong passphrase accepted for " + cipher);
        }
        catch (IllegalStateException expected)
        {
            // expected
        }

        // the single-argument entry point must report that a passphrase is required
        try
        {
            OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(blob);
            fail("missing passphrase accepted for " + cipher);
        }
        catch (IllegalStateException expected)
        {
            isEquals(expected.getMessage(), "passphrase required to decrypt encrypted OpenSSH private key");
        }
    }

    private String keyMaterial(AsymmetricKeyParameter key)
    {
        if (key instanceof Ed25519PrivateKeyParameters)
        {
            return Hex.toHexString(((Ed25519PrivateKeyParameters)key).getEncoded());
        }
        if (key instanceof RSAPrivateCrtKeyParameters)
        {
            return ((RSAPrivateCrtKeyParameters)key).getModulus().toString(16);
        }
        if (key instanceof ECPrivateKeyParameters)
        {
            return ((ECPrivateKeyParameters)key).getD().toString(16);
        }
        throw new IllegalStateException("unexpected key type: " + key.getClass().getName());
    }

    public String getName()
    {
        return "OpenSSHParsing";
    }

    public void performTest()
        throws Exception
    {
        testECDSA_curvesFromSSHKeyGen();
        testDSA();
        testECDSA();
        testRSA();
        testED25519();
        testFailures();
        testFido2Keys();
        testECDSAEncodeOpenSSHFormat();
        testEncryptedKeys();
    }

    /**
     * github #2240 - ensure encodePrivateKey for ECDSA emits the openssh-key-v1
     * envelope (not the raw RFC 5915 ECPrivateKey SEQUENCE) so the output is
     * compatible with OpenSSH and JSCH.
     */
    public void testECDSAEncodeOpenSSHFormat()
        throws Exception
    {
        org.bouncycastle.crypto.generators.ECKeyPairGenerator kpg =
            new org.bouncycastle.crypto.generators.ECKeyPairGenerator();
        org.bouncycastle.asn1.x9.X9ECParameters x9 =
            org.bouncycastle.asn1.nist.NISTNamedCurves.getByName("P-256");
        org.bouncycastle.crypto.params.ECDomainParameters domain =
            new org.bouncycastle.crypto.params.ECNamedDomainParameters(
                org.bouncycastle.asn1.sec.SECObjectIdentifiers.secp256r1, x9);
        kpg.init(new org.bouncycastle.crypto.params.ECKeyGenerationParameters(domain, secureRandom));
        org.bouncycastle.crypto.AsymmetricCipherKeyPair pair = kpg.generateKeyPair();
        ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters)pair.getPrivate();

        byte[] encoded = OpenSSHPrivateKeyUtil.encodePrivateKey(privateKey);

        byte[] expectedMagic = org.bouncycastle.util.Strings.toByteArray("openssh-key-v1\0");
        if (encoded.length < expectedMagic.length)
        {
            fail("ECDSA OpenSSH-encoded key too short");
        }
        for (int i = 0; i < expectedMagic.length; i++)
        {
            if (encoded[i] != expectedMagic[i])
            {
                fail("ECDSA OpenSSH-encoded key missing openssh-key-v1 magic at byte " + i);
            }
        }

        // Round-trip via the parser; recovered scalar must match.
        ECPrivateKeyParameters recovered = (ECPrivateKeyParameters)
            OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(encoded);
        if (!privateKey.getD().equals(recovered.getD()))
        {
            fail("ECDSA round-trip lost the private scalar");
        }

        // Also confirm a sign / verify works end-to-end.
        ECPoint q = privateKey.getParameters().getG().multiply(privateKey.getD()).normalize();
        doECSigTest(new org.bouncycastle.crypto.params.ECPublicKeyParameters(q, privateKey.getParameters()),
            privateKey);
    }

    public void testRSA()
        throws Exception
    {
        CipherParameters pubSpec = OpenSSHPublicKeyUtil.parsePublicKey(Base64.decode("AAAAB3NzaC1yc2EAAAADAQABAAAAgQDvh2BophdIp8ojwGZQR0FQ/awowXnV24nAPm+/na8MOUrdySNhOnlek4LAZl82/+Eu2t21XD6hQUiHKAj6XaNFBthTuss7Cz/tA348DLEMHD9wUtT0FXVmsxqN4BfusunbcULxxVWG2z8FvqeaGgc/Unkp9y7/kyf54pPUCBcClw=="));

        CipherParameters privSpec = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(new PemReader(new StringReader("-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIICXgIBAAKBgQDvh2BophdIp8ojwGZQR0FQ/awowXnV24nAPm+/na8MOUrdySNh\n" +
            "Onlek4LAZl82/+Eu2t21XD6hQUiHKAj6XaNFBthTuss7Cz/tA348DLEMHD9wUtT0\n" +
            "FXVmsxqN4BfusunbcULxxVWG2z8FvqeaGgc/Unkp9y7/kyf54pPUCBcClwIDAQAB\n" +
            "AoGBAOMXYEoXHgAeREE9CkOWKtDUkEJbnF0rNSB0kZIDt5BJSTeYmNh3jdYi2FX9\n" +
            "OMx2MFIx4v0tJZvQvyiUxl5IJJ9ZJsYUWF+6VbcTVwYYfdVzZzP2TNyGmF9/ADZW\n" +
            "wBehqP04uRlYjt94kqb4HoOKF3gJ3LC4uW9xcEltTBeHWCfhAkEA/2biF5St9/Ya\n" +
            "540E4zu/FKPsxLSaT8LWCo9+X7IqIzlBQCB4GjM+nZeTm7eZOkfAFZoxwfiNde/9\n" +
            "qleXXf6B2QJBAPAW+jDBC3QF4/g8n9cDxm/A3ICmcOFSychLSrydk9ZyRPbTRyQC\n" +
            "YlC2mf/pCrO/yO7h189BXyQ3PXOEhnujce8CQQD7gDy0K90EiH0F94AQpA0OLj5B\n" +
            "lfc/BAXycEtpwPBtrzvqAg9C/aNzXIgmly10jqNAoo7NDA2BTcrlq0uLa8xBAkBl\n" +
            "7Hs+I1XnZXDIO4Rn1VRysN9rRj15ipnbDAuoUwUl7tDUMBFteg2e0kZCW/6NHIgC\n" +
            "0aG6fLgVOdY+qi4lYtfFAkEAqqiBgEgSrDmnJLTm6j/Pv1mBA6b9bJbjOqomrDtr\n" +
            "AWTXe+/kSCv/jYYdpNA/tDgAwEmtkWWEie6+SwJB5cXXqg==\n" +
            "-----END RSA PRIVATE KEY-----\n")).readPemObject().getContent());

        doRSATest(pubSpec, privSpec);

        privSpec = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(new PemReader(new StringReader(rsa1024Key)).readPemObject().getContent());
        pubSpec = new RSAKeyParameters(false, ((RSAKeyParameters)privSpec).getModulus(), ((RSAPrivateCrtKeyParameters)privSpec).getPublicExponent());

        doRSATest(pubSpec, privSpec);

        privSpec = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(new PemReader(new StringReader(rsa2048Key)).readPemObject().getContent());
        pubSpec = new RSAKeyParameters(false, ((RSAKeyParameters)privSpec).getModulus(), ((RSAPrivateCrtKeyParameters)privSpec).getPublicExponent());

        doRSATest(pubSpec, privSpec);

        privSpec = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(new PemReader(new StringReader(rsa3072Key)).readPemObject().getContent());
        pubSpec = new RSAKeyParameters(false, ((RSAKeyParameters)privSpec).getModulus(), ((RSAPrivateCrtKeyParameters)privSpec).getPublicExponent());

        doRSATest(pubSpec, privSpec);
        
        privSpec = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(new PemReader(new StringReader(rsa4096Key)).readPemObject().getContent());
        pubSpec = new RSAKeyParameters(false, ((RSAKeyParameters)privSpec).getModulus(), ((RSAPrivateCrtKeyParameters)privSpec).getPublicExponent());

        doRSATest(pubSpec, privSpec);
    }

    private void doRSATest(CipherParameters pubSpec, CipherParameters privSpec)
            throws Exception
        {
            byte[] originalMessage = new byte[10];
            secureRandom.nextBytes(originalMessage);

            originalMessage[0] |= 1;

            RSAEngine rsaEngine = new RSAEngine();
            rsaEngine.init(true, privSpec);

            byte[] ct = rsaEngine.processBlock(originalMessage, 0, originalMessage.length);

            rsaEngine.init(false, pubSpec);
            byte[] result = rsaEngine.processBlock(ct, 0, ct.length);

            isTrue("Result did not match original message", Arrays.areEqual(originalMessage, result));

        }
}
