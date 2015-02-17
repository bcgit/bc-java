package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.agreement.srp.SRP6Client;
import org.bouncycastle.crypto.agreement.srp.SRP6Server;
import org.bouncycastle.crypto.agreement.srp.SRP6StandardGroups;
import org.bouncycastle.crypto.agreement.srp.SRP6Util;
import org.bouncycastle.crypto.agreement.srp.SRP6VerifierGenerator;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.DHParametersGenerator;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.SRP6GroupParameters;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class SRP6Test extends SimpleTest
{
    private static final BigInteger ZERO = BigInteger.valueOf(0);

    private static BigInteger fromHex(String hex)
    {
        return new BigInteger(1, Hex.decode(hex));
    }

    private final SecureRandom random = new SecureRandom();

    public String getName()
    {
        return "SRP6";
    }

    public void performTest() throws Exception
    {
        rfc5054AppendixBTestVectors();

        testMutualVerification(SRP6StandardGroups.rfc5054_1024);
        testClientCatchesBadB(SRP6StandardGroups.rfc5054_1024);
        testServerCatchesBadA(SRP6StandardGroups.rfc5054_1024);

        testWithRandomParams(256);
        testWithRandomParams(384);
        testWithRandomParams(512);
    }

    private void rfc5054AppendixBTestVectors() throws Exception
    {
        byte[] I = "alice".getBytes("UTF8");
        byte[] P = "password123".getBytes("UTF8");
        byte[] s = Hex.decode("BEB25379D1A8581EB5A727673A2441EE");
        BigInteger N = SRP6StandardGroups.rfc5054_1024.getN();
        BigInteger g = SRP6StandardGroups.rfc5054_1024.getG();
        BigInteger a = fromHex("60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393");
        BigInteger b = fromHex("E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20");

        BigInteger expect_k = fromHex("7556AA045AEF2CDD07ABAF0F665C3E818913186F");
        BigInteger expect_x = fromHex("94B7555AABE9127CC58CCF4993DB6CF84D16C124");
        BigInteger expect_v = fromHex("7E273DE8696FFC4F4E337D05B4B375BEB0DDE1569E8FA00A9886D812"
            + "9BADA1F1822223CA1A605B530E379BA4729FDC59F105B4787E5186F5"
            + "C671085A1447B52A48CF1970B4FB6F8400BBF4CEBFBB168152E08AB5"
            + "EA53D15C1AFF87B2B9DA6E04E058AD51CC72BFC9033B564E26480D78"
            + "E955A5E29E7AB245DB2BE315E2099AFB");
        BigInteger expect_A = fromHex("61D5E490F6F1B79547B0704C436F523DD0E560F0C64115BB72557EC4"
            + "4352E8903211C04692272D8B2D1A5358A2CF1B6E0BFCF99F921530EC"
            + "8E39356179EAE45E42BA92AEACED825171E1E8B9AF6D9C03E1327F44"
            + "BE087EF06530E69F66615261EEF54073CA11CF5858F0EDFDFE15EFEA"
            + "B349EF5D76988A3672FAC47B0769447B");
        BigInteger expect_B = fromHex("BD0C61512C692C0CB6D041FA01BB152D4916A1E77AF46AE105393011"
            + "BAF38964DC46A0670DD125B95A981652236F99D9B681CBF87837EC99"
            + "6C6DA04453728610D0C6DDB58B318885D7D82C7F8DEB75CE7BD4FBAA"
            + "37089E6F9C6059F388838E7A00030B331EB76840910440B1B27AAEAE"
            + "EB4012B7D7665238A8E3FB004B117B58");
        BigInteger expect_u = fromHex("CE38B9593487DA98554ED47D70A7AE5F462EF019");
        BigInteger expect_S = fromHex("B0DC82BABCF30674AE450C0287745E7990A3381F63B387AAF271A10D"
            + "233861E359B48220F7C4693C9AE12B0A6F67809F0876E2D013800D6C"
            + "41BB59B6D5979B5C00A172B4A2A5903A0BDCAF8A709585EB2AFAFA8F"
            + "3499B200210DCC1F10EB33943CD67FC88A2F39A4BE5BEC4EC0A3212D"
            + "C346D7E474B29EDE8A469FFECA686E5A");

        BigInteger k = SRP6Util.calculateK(new SHA1Digest(), N, g);
        if (!k.equals(expect_k))
        {
            fail("wrong value of 'k'");
        }

        BigInteger x = SRP6Util.calculateX(new SHA1Digest(), N, s, I, P);
        if (!x.equals(expect_x))
        {
            fail("wrong value of 'x'");
        }

        SRP6VerifierGenerator gen = new SRP6VerifierGenerator();
        gen.init(N, g, new SHA1Digest());
        BigInteger v = gen.generateVerifier(s, I, P);
        if (!v.equals(expect_v))
        {
            fail("wrong value of 'v'");
        }

        final BigInteger aVal = a;
        SRP6Client client = new SRP6Client()
        {
            protected BigInteger selectPrivateValue()
            {
                return aVal;
            }
        };
        client.init(N, g, new SHA1Digest(), random);

        BigInteger A = client.generateClientCredentials(s, I, P);
        if (!A.equals(expect_A))
        {
            fail("wrong value of 'A'");
        }

        final BigInteger bVal = b;
        SRP6Server server = new SRP6Server()
        {
            protected BigInteger selectPrivateValue()
            {
                return bVal;
            }
        };
        server.init(N, g, v, new SHA1Digest(), random);

        BigInteger B = server.generateServerCredentials();
        if (!B.equals(expect_B))
        {
            fail("wrong value of 'B'");
        }

        BigInteger u = SRP6Util.calculateU(new SHA1Digest(), N, A, B);
        if (!u.equals(expect_u))
        {
            fail("wrong value of 'u'");
        }

        BigInteger clientS = client.calculateSecret(B);
        if (!clientS.equals(expect_S))
        {
            fail("wrong value of 'S' (client)");
        }

        BigInteger serverS = server.calculateSecret(A);
        if (!serverS.equals(expect_S))
        {
            fail("wrong value of 'S' (server)");
        }
    }

    private void testWithRandomParams(int bits) throws CryptoException
    {
        DHParametersGenerator paramGen = new DHParametersGenerator();
        paramGen.init(bits, 25, random);
        DHParameters parameters = paramGen.generateParameters();

        testMutualVerification(new SRP6GroupParameters(parameters.getP(), parameters.getG()));
    }

    private void testMutualVerification(SRP6GroupParameters group) throws CryptoException
    {
        byte[] I = "username".getBytes();
        byte[] P = "password".getBytes();
        byte[] s = new byte[16];
        random.nextBytes(s);

        SRP6VerifierGenerator gen = new SRP6VerifierGenerator();
        gen.init(group, new SHA256Digest());
        BigInteger v = gen.generateVerifier(s, I, P);

        SRP6Client client = new SRP6Client();
        client.init(group, new SHA256Digest(), random);

        SRP6Server server = new SRP6Server();
        server.init(group, v, new SHA256Digest(), random);

        BigInteger A = client.generateClientCredentials(s, I, P);
        BigInteger B = server.generateServerCredentials();

        BigInteger clientS = client.calculateSecret(B);
        BigInteger serverS = server.calculateSecret(A);

        if (!clientS.equals(serverS))
        {
            fail("SRP agreement failed - client/server calculated different secrets");
        }
    }

    private void testClientCatchesBadB(SRP6GroupParameters group)
    {
        byte[] I = "username".getBytes();
        byte[] P = "password".getBytes();
        byte[] s = new byte[16];
        random.nextBytes(s);

        SRP6Client client = new SRP6Client();
        client.init(group, new SHA256Digest(), random);

        client.generateClientCredentials(s, I, P);

        try
        {
            client.calculateSecret(ZERO);
            fail("Client failed to detect invalid value for 'B'");
        }
        catch (CryptoException e)
        {
            // Expected
        }

        try
        {
            client.calculateSecret(group.getN());
            fail("Client failed to detect invalid value for 'B'");
        }
        catch (CryptoException e)
        {
            // Expected
        }
    }

    private void testServerCatchesBadA(SRP6GroupParameters group)
    {
        byte[] I = "username".getBytes();
        byte[] P = "password".getBytes();
        byte[] s = new byte[16];
        random.nextBytes(s);

        SRP6VerifierGenerator gen = new SRP6VerifierGenerator();
        gen.init(group, new SHA256Digest());
        BigInteger v = gen.generateVerifier(s, I, P);

        SRP6Server server = new SRP6Server();
        server.init(group, v, new SHA256Digest(), random);

        server.generateServerCredentials();

        try
        {
            server.calculateSecret(ZERO);
            fail("Client failed to detect invalid value for 'A'");
        }
        catch (CryptoException e)
        {
            // Expected
        }

        try
        {
            server.calculateSecret(group.getN());
            fail("Client failed to detect invalid value for 'A'");
        }
        catch (CryptoException e)
        {
            // Expected
        }
    }

    public static void main(String[] args)
    {
        runTest(new SRP6Test());
    }
}

