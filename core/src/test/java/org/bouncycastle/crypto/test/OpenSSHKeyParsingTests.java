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
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Tests for the lightweight OpenSSH public and private key parsers.
 * <p>
 * NOT-A-SECRET: openssh test vector. Every private key in this file is a deliberately published
 * test fixture. Each was generated for this test suite with no passphrase and has never protected
 * anything; they exist so the parser can be exercised against real ssh-keygen output. Automated
 * secret scanners flag them, and that is a false positive - there is nothing here to rotate or
 * report.
 * <p>
 * All of them carry the comment "bc-test-vector". A new vector should be generated the same way,
 * with ssh-keygen -C bc-test-vector, so that no user name or host name of whoever produced it is
 * carried in the key's comment field, where it is invisible in the source but recoverable by
 * anyone who decodes the blob (github #2376).
 */
public class OpenSSHKeyParsingTests
    extends SimpleTest
{
    private static SecureRandom secureRandom = new SecureRandom();

    String rsa1024Key =
          "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn\n"
        + "NhAAAAAwEAAQAAAIEArHxYlw5KneueM5BRNptr49S9ANg2/a4LARArZXxQzP+p4Mu6aIK2\n"
        + "v1su4/RIFrucu7dLy1l2Xs4gofX16IIlXy7GROeB4DaQ/5hnQVwX0B/lsKxvelqxp91x5a\n"
        + "2cVQH+S2GikJex3glsqXxJ012dFXEAQhozdg8ePaHIwSy0BAkAAAIIop50TaKedE0AAAAH\n"
        + "c3NoLXJzYQAAAIEArHxYlw5KneueM5BRNptr49S9ANg2/a4LARArZXxQzP+p4Mu6aIK2v1\n"
        + "su4/RIFrucu7dLy1l2Xs4gofX16IIlXy7GROeB4DaQ/5hnQVwX0B/lsKxvelqxp91x5a2c\n"
        + "VQH+S2GikJex3glsqXxJ012dFXEAQhozdg8ePaHIwSy0BAkAAAADAQABAAAAgFLSnoNiJG\n"
        + "gyFFP0L1sGREcxBtRZ/gXPxY7sIbpoeDAHb532lXrLkU7PTPO+f8MSsU7d0/I/8fvSBI9g\n"
        + "mITdwW1qKrluvD5j2MQXdad/5nB16e9RrtU5tdYCFzqbkmjnSVFXoXfQ4o4+Cc2EmoY7JI\n"
        + "BJ3KAbxY3DpUaUVh7lxf4FAAAAQDqoSLhZPHMDe2OYv5feYTLt/f0SF5Eu4u/Adk98AbXB\n"
        + "P/Ky1k+s3SmaTHaPovqOE1RJtNEyBpmKCmdQaNmLtXIAAABBANRaek3/A8aIyO+n7Uclza\n"
        + "gUsPzAkOKh1jXWUCmbtRfb1GKmY8VH9o76RhJhfSpHGVKJmvqpUgk1BLlgVBTabmcAAABB\n"
        + "AM/wIGVJhDqsZPYxzepA4Bxw494h/5mRvsQP4E1eIeweJe5oUWkFmUeq+IZWyW1fgeVdXI\n"
        + "OUDYtjvdY0SX7MlA8AAAAOYmMtdGVzdC12ZWN0b3IBAgMEBQ==\n"
        + "-----END OPENSSH PRIVATE KEY-----\n";
      String rsa2048Key =
          "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + "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\n"
        + "-----END OPENSSH PRIVATE KEY-----\n";
      String rsa3072Key =
          "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + "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\n"
        + "-----END OPENSSH PRIVATE KEY-----\n";
      String rsa4096Key =
          "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAACFwAAAAdzc2gtcn\n"
        + "NhAAAAAwEAAQAAAgEA1fO+2KzZ+KjE5ESyHThNNCL+UOCPd1+9/UjyA8vcTTa4NA+kcslI\n"
        + "Gh+kURdk9b/7enCqotPodhoznx2o6yDXOmXf6Bv/jlMtsu2r5M9JG/mgjI5DeJuM9PqCvW\n"
        + "M8hn80DhNYFNbRnjj9psBYpVnimnAk0N1I0lUuwoGwJ6nz6LBAfPvrkDsVxvtbWM728gxh\n"
        + "QQXs0xmUhI/aLEbyuJvu6vshs0IQUFRRFhjvFB+bvYhCszAmPrThRQF0QE6tzXeXYxh/5N\n"
        + "ly68SPfpS331BL6sQ1MO3h+GgQbzK+Kk/m3pNiyKfWR0CSaTFjIzgZ/EDTtWkXTwonCGfj\n"
        + "ZU2Z3XpQ2vMHYMlzyPJMvdweYB3GNJqzldD1ICHBt2LPGYhOa39f5sV/o5piXe8ZF2BxbF\n"
        + "FbIb/OTFfy30wvHGYSfzGVbvRo0G2O/9MT11f1vKJGwr58D5SLIXPLkJ+VoCHgCj5jqxZA\n"
        + "i2XcVE+YeS4mY5zU4hGSrLUUdL4OIZULUMz1GAuf82wkcaVy9xD5CbBVm50rUy36sCgzKL\n"
        + "i1Sb7P1oQVssKxjI7rOkp8LL3WurjprUHeGMS/4cAYDUwUgy7ZjJNnGQmlqANdOiXALfvF\n"
        + "pdN3xIYU3PHrLohYbuu3p/LOFHG13M90d1QPmkpv1Xn6KGr5ZnYEGtkjih0RbOWdJtfjZM\n"
        + "8AAAdI3wjz1t8I89YAAAAHc3NoLXJzYQAAAgEA1fO+2KzZ+KjE5ESyHThNNCL+UOCPd1+9\n"
        + "/UjyA8vcTTa4NA+kcslIGh+kURdk9b/7enCqotPodhoznx2o6yDXOmXf6Bv/jlMtsu2r5M\n"
        + "9JG/mgjI5DeJuM9PqCvWM8hn80DhNYFNbRnjj9psBYpVnimnAk0N1I0lUuwoGwJ6nz6LBA\n"
        + "fPvrkDsVxvtbWM728gxhQQXs0xmUhI/aLEbyuJvu6vshs0IQUFRRFhjvFB+bvYhCszAmPr\n"
        + "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\n"
        + "-----END OPENSSH PRIVATE KEY-----\n";
      String ecdsa256Key =
          "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS\n"
        + "1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQRIRlwdiXo7rxAFRrZzh0H8Qc0/sJDi\n"
        + "IMsTMAz9sHEMMhdzsIJG9zuAu9Dn6gEQEX8CGX4IU/fmyryvcOr+H5YRAAAAqJeV5aWXle\n"
        + "WlAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEhGXB2JejuvEAVG\n"
        + "tnOHQfxBzT+wkOIgyxMwDP2wcQwyF3Owgkb3O4C70OfqARARfwIZfghT9+bKvK9w6v4flh\n"
        + "EAAAAgD/q7DOljUEubZzlQ0Hfgkya97S8vufqSfvX6yxlIEHIAAAAOYmMtdGVzdC12ZWN0\n"
        + "b3IBAg==\n"
        + "-----END OPENSSH PRIVATE KEY-----\n";
      String ecdsa384Key =
          "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAiAAAABNlY2RzYS\n"
        + "1zaGEyLW5pc3RwMzg0AAAACG5pc3RwMzg0AAAAYQQB/Ra7uLuQ0/Jx35q7KHbUaYJhMfZm\n"
        + "iDwirxPs6xt40s290V7N2Yw0VIqVj9MnaXogb7ZZgw9jhhlQwAjfeYe3qfF7i/EqD8N4+K\n"
        + "6ctU5xZxWfFiQapfImqmNvqTbgrLMAAADYfTU/bn01P24AAAATZWNkc2Etc2hhMi1uaXN0\n"
        + "cDM4NAAAAAhuaXN0cDM4NAAAAGEEAf0Wu7i7kNPycd+auyh21GmCYTH2Zog8Iq8T7OsbeN\n"
        + "LNvdFezdmMNFSKlY/TJ2l6IG+2WYMPY4YZUMAI33mHt6nxe4vxKg/DePiunLVOcWcVnxYk\n"
        + "GqXyJqpjb6k24KyzAAAAMQCZJCteemrRab5c41mFam/zxnSwZDaRrTyqCg4fFBSJ/OSApE\n"
        + "dbdhoKUJH/hlh7hQwAAAAOYmMtdGVzdC12ZWN0b3IB\n"
        + "-----END OPENSSH PRIVATE KEY-----\n";
      String ecdsa521Key =
          "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAArAAAABNlY2RzYS\n"
        + "1zaGEyLW5pc3RwNTIxAAAACG5pc3RwNTIxAAAAhQQAUEwMM6VQTjti6uHCN1sYUyAYw59/\n"
        + "043JTjt3VCpOwMNrP/bXm8nbk8Wl32vH5g6rD8RkypL5m2QyIaZCmp/FlqoAuH1Nda7NFS\n"
        + "4Hf8Rj+/cWfUavKyITU+pv/77nrOaP8O1D2K+CGgjOWrVsmO4YC6pfXVs56M4CiAJGIzge\n"
        + "j1NCXQsAAAEQQahzLUGocy0AAAATZWNkc2Etc2hhMi1uaXN0cDUyMQAAAAhuaXN0cDUyMQ\n"
        + "AAAIUEAFBMDDOlUE47YurhwjdbGFMgGMOff9ONyU47d1QqTsDDaz/215vJ25PFpd9rx+YO\n"
        + "qw/EZMqS+ZtkMiGmQpqfxZaqALh9TXWuzRUuB3/EY/v3Fn1GrysiE1Pqb/++56zmj/DtQ9\n"
        + "ivghoIzlq1bJjuGAuqX11bOejOAogCRiM4Ho9TQl0LAAAAQgGisar55LdiArjlfj5hzb8M\n"
        + "rshedrTzWGySZLsV4XE3NziOOWdzW4ulJljkpSgs6tcjWgj38KyOrFG9X5bzGuWcNgAAAA\n"
        + "5iYy10ZXN0LXZlY3RvcgECAwQ=\n"
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
                "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAKBZPxIGfC8AaGcd9zEYESqI0VuqKuFUFV6lMH2IpQAdTF0gBKx2ZPb72b/RtOh+zrCfgWss4E/eA6NCR4D8Vo=",
                "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
                    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS\n" +
                    "1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQQCgWT8SBnwvAGhnHfcxGBEqiNFbqir\n" +
                    "hVBVepTB9iKUAHUxdIASsdmT2+9m/0bTofs6wn4FrLOBP3gOjQkeA/FaAAAAqE0Y9FRNGP\n" +
                    "RUAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAKBZPxIGfC8AaGc\n" +
                    "d9zEYESqI0VuqKuFUFV6lMH2IpQAdTF0gBKx2ZPb72b/RtOh+zrCfgWss4E/eA6NCR4D8V\n" +
                    "oAAAAhANfjzbm9xAVduJHicnCMay8r5Ui8wGRBdjlKYEBSTAcHAAAADmJjLXRlc3QtdmVj\n" +
                    "dG9yAQ==\n" +
                    "-----END OPENSSH PRIVATE KEY-----\n"
            },
            {
                "AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBHF+Kr54ITOI4lKOhB77LaTXTKvM7MZ52CTbCA2yHwJpFwizMSyikpWppwzSigVbiBdzIdpM7cv4RCzI60H77BzBtVIf5HsmpVxm66F3B9HiZHZclxaigCRdmgrdV5rcvw==",
                "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
                    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAiAAAABNlY2RzYS\n" +
                    "1zaGEyLW5pc3RwMzg0AAAACG5pc3RwMzg0AAAAYQRxfiq+eCEziOJSjoQe+y2k10yrzOzG\n" +
                    "edgk2wgNsh8CaRcIszEsopKVqacM0ooFW4gXcyHaTO3L+EQsyOtB++wcwbVSH+R7JqVcZu\n" +
                    "uhdwfR4mR2XJcWooAkXZoK3Vea3L8AAADYc5gGnXOYBp0AAAATZWNkc2Etc2hhMi1uaXN0\n" +
                    "cDM4NAAAAAhuaXN0cDM4NAAAAGEEcX4qvnghM4jiUo6EHvstpNdMq8zsxnnYJNsIDbIfAm\n" +
                    "kXCLMxLKKSlamnDNKKBVuIF3Mh2kzty/hELMjrQfvsHMG1Uh/keyalXGbroXcH0eJkdlyX\n" +
                    "FqKAJF2aCt1Xmty/AAAAMQDekGLsIlDZK97HK/kdzFhORnnb3dsuZZMkBBfVtkI0jthT5b\n" +
                    "74EKoaL12AmG+SSaEAAAAOYmMtdGVzdC12ZWN0b3IB\n" +
                    "-----END OPENSSH PRIVATE KEY-----\n"
            },
            {
                "AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBACbaye9fGFxgovjdFGZce4R9MhXxjK47exmSXoBJisSeaeYvJnEfOGkV9tKezjwQfXStouQvNRP8UwGT9irFH7mrwGfLAns8303vkxwc3QdN5/DvyruwBOjWrshV/UiPeZnrcevonrZ5S82UsPEHtu95PdkDOVsMLU2wpJ/CenGCBrJeQ==",
                "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
                    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAArAAAABNlY2RzYS\n" +
                    "1zaGEyLW5pc3RwNTIxAAAACG5pc3RwNTIxAAAAhQQAm2snvXxhcYKL43RRmXHuEfTIV8Yy\n" +
                    "uO3sZkl6ASYrEnmnmLyZxHzhpFfbSns48EH10raLkLzUT/FMBk/YqxR+5q8BnywJ7PN9N7\n" +
                    "5McHN0HTefw78q7sATo1q7IVf1Ij3mZ63Hr6J62eUvNlLDxB7bveT3ZAzlbDC1NsKSfwnp\n" +
                    "xggayXkAAAEQm7wB+Zu8AfkAAAATZWNkc2Etc2hhMi1uaXN0cDUyMQAAAAhuaXN0cDUyMQ\n" +
                    "AAAIUEAJtrJ718YXGCi+N0UZlx7hH0yFfGMrjt7GZJegEmKxJ5p5i8mcR84aRX20p7OPBB\n" +
                    "9dK2i5C81E/xTAZP2KsUfuavAZ8sCezzfTe+THBzdB03n8O/Ku7AE6NauyFX9SI95metx6\n" +
                    "+ietnlLzZSw8Qe273k92QM5WwwtTbCkn8J6cYIGsl5AAAAQgEyAAEsE1VnZzrLkwBJFLCx\n" +
                    "ArZ85tjuVicLpGPif6tcA9MwRFTBuERWPTEMqSD+WXf7N/ey/0K+BjTbokNseWLo3AAAAA\n" +
                    "5iYy10ZXN0LXZlY3RvcgECAwQ=\n" +
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

        CipherParameters pubSpec = OpenSSHPublicKeyUtil.parsePublicKey(Base64.decode("AAAAC3NzaC1lZDI1NTE5AAAAIM8WklYS64PF4pjk1kvRPno981YfTRHc/KabXnvvPznQ"));

        CipherParameters privSpec = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(new PemReader(new StringReader("-----BEGIN OPENSSH PRIVATE KEY-----\n" +
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n" +
            "QyNTUxOQAAACDPFpJWEuuDxeKY5NZL0T56PfNWH00R3Pymm1577z850AAAAJjTBGM30wRj\n" +
            "NwAAAAtzc2gtZWQyNTUxOQAAACDPFpJWEuuDxeKY5NZL0T56PfNWH00R3Pymm1577z850A\n" +
            "AAAEAKiSXzpYE+U3lVn9Gi0PrnrtmmnsDvv/NtzYFa334px88WklYS64PF4pjk1kvRPno9\n" +
            "81YfTRHc/KabXnvvPznQAAAADmJjLXRlc3QtdmVjdG9yAQIDBAUGBw==\n" +
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
        // An empty blob must be rejected with a typed exception, not an ArrayIndexOutOfBoundsException
        // from the leading blob[0] format probe in parsePrivateKeyBlob.
        try
        {
            OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(new byte[0]);
            fail("empty blob should be rejected");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("empty blob rejection", e.getMessage(), "blob is null or empty");
        }

        byte[] blob = new PemReader(new StringReader("-----BEGIN OPENSSH PRIVATE KEY-----\n" +
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n" +
            "QyNTUxOQAAACB/AEpQ+Tcr574EgK2aoUET8cUUKFDM4EZ6LE6mM3XdtgAAAJhRODnmUTg5\n" +
            "5gAAAAtzc2gtZWQyNTUxOQAAACB/AEpQ+Tcr574EgK2aoUET8cUUKFDM4EZ6LE6mM3Xdtg\n" +
            "AAAECzL33Ny2MkyL4hcrz9fmnN+DZS/kWltzljROCZK6hLGH8ASlD5NyvnvgSArZqhQRPx\n" +
            "xRQoUMzgRnosTqYzdd22AAAADmJjLXRlc3QtdmVjdG9yAQIDBAUGBw==\n" +
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
            "QyNTUxOQAAACDqOl8UnmjXIkoygWL9jjlcGbAzYqFgeKRb8oOO1xiw6AAAAJjcxo823MaP\n" +
            "NgAAAAtzc2gtZWQyNTUxOQAAACDqOl8UnmjXIkoygWL9jjlcGbAzYqFgeKRb8oOO1xiw6A\n" +
            "AAAEBXt2Q56uHVwS7EU+ULpnzwX5Ei8BarRz/fnmAX+zd1C+o6XxSeaNciSjKBYv2OOVwZ\n" +
            "sDNioWB4pFvyg47XGLDoAAAADmJjLXRlc3QtdmVjdG9yAQIDBAUGBw==\n" +
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

    /**
     * The bcrypt round count is read from the key's own kdfoptions and drives the KDF before
     * anything about the key has been verified, so it has to be bounded: a round costs several
     * milliseconds and the wire format allows up to 2^31-1 of them, which is CPU-months from a
     * key file of a few hundred bytes. This is the OpenSSH member of the *_MAX_IT_COUNT family
     * and the only one that had no cap at all.
     * <p>
     * The fixture below is a normal ssh-keygen key at its default of 16 rounds, so the cap is
     * lowered under it rather than a hostile key being hand-built - the same approach as
     * BCFKSStoreTest.shouldRejectExcessiveMacKdfCost.
     */
    public void testEncryptedKeyRoundsBounded()
        throws Exception
    {
        String pem =
            "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
            "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABD4XaoKXH\n" +
            "N9dMM5dz+nRBC6AAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIHs3/Bh5SIn8aexd\n" +
            "42KtdGV83J4+sckvemTmsG0u6uOyAAAAkBLLK8FUZ0ErL2dC/3fDEz+MdA6MMVZv0Q83OJ\n" +
            "5AbQ0WvN0wLo6lARyiiZm2L4Z3rO5XGkY+BpDrNUI1iKNd39VdgyBLX+u0dbJ/EI5ZXMYs\n" +
            "j5iVU+CD0fJc7KrToTDvblDoS3jeW9yXrLdnV5Mi25gdQLojq8x3px2Dv+HoqT3vTuAivl\n" +
            "ISNUnmozjANHauJg==\n" +
            "-----END OPENSSH PRIVATE KEY-----\n";

        byte[] blob = new PemReader(new StringReader(pem)).readPemObject().getContent();
        byte[] passphrase = Strings.toByteArray("Test1234!");

        String old = System.getProperty(Properties.OPENSSH_MAX_ROUNDS);
        System.setProperty(Properties.OPENSSH_MAX_ROUNDS, "8");
        try
        {
            OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(blob, passphrase);
            fail("bcrypt round count above the configured cap accepted");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("unexpected message: " + e.getMessage(),
                e.getMessage().indexOf("bcrypt rounds (16) greater than 8") >= 0);
        }
        finally
        {
            if (old == null)
            {
                System.getProperties().remove(Properties.OPENSSH_MAX_ROUNDS);
            }
            else
            {
                System.setProperty(Properties.OPENSSH_MAX_ROUNDS, old);
            }
        }

        // the compatibility assertion: under the default cap the same key still decrypts
        isEquals("key no longer parses under the default cap",
            "0ad120d52190b5a6edf251e51e9eedf70acc46b3643d72c9ae952021afc1af68",
            keyMaterial(OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(blob, passphrase)));
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
        testEncryptedKeyRoundsBounded();
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
