package org.bouncycastle.crypto.test;

import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.Test;

public final class RegressionTest
{
    public static Test[]    tests = {
            new AESTest(),
        new DESTest(),
        new DESedeTest(),
        new ModeTest(),
        new DHTest(),
        new ElGamalTest(),
        new DSATest(),
        new ECTest(),
        new ECIESTest(),
        new MacTest(),
        new RC2Test(),
        new RC4Test(),
        new RC5Test(),
        new RC6Test(),
        new RijndaelTest(),
        new SerpentTest(),
        new SkipjackTest(),
        new BlowfishTest(),
        new TwofishTest(),
        new CAST5Test(),
        new CAST6Test(),
        new IDEATest(),
        new CamelliaTest(),
        new RSATest(),
        new ISO9796Test(),
        new MD2DigestTest(),
        new MD4DigestTest(),
        new MD5DigestTest(),
        new SHA1DigestTest(),
        new SHA256DigestTest(),
        new SHA384DigestTest(),
        new SHA512DigestTest(),
        new RIPEMD128DigestTest(),
        new RIPEMD160DigestTest(),
        new TigerDigestTest(),
        new MD5HMacTest(),
        new SHA1HMacTest(),
        new RIPEMD128HMacTest(),
        new RIPEMD160HMacTest(),
        new OAEPTest(),
        new PSSTest(),
        new CTSTest(),
        new PKCS5Test(),
        new PKCS12Test(),
        new GOST28147Test(),
        new GOST3410Test(),
        new WhirlpoolDigestTest()
    };

    public static void main(String[] args)
    {
        SimpleTest.runTests(tests);
    }
}
