package org.bouncycastle.crypto.test;

import java.math.BigInteger;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.signers.X931Signer;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class X931SignerTest
    extends SimpleTest
{
    public String getName()
    {
        return "X931Signer";
    }

    public void performTest() throws Exception
    {
        BigInteger rsaPubMod = new BigInteger(Base64.decode("AIASoe2PQb1IP7bTyC9usjHP7FvnUMVpKW49iuFtrw/dMpYlsMMoIU2jupfifDpdFxIktSB4P+6Ymg5WjvHKTIrvQ7SR4zV4jaPTu56Ys0pZ9EDA6gb3HLjtU+8Bb1mfWM+yjKxcPDuFjwEtjGlPHg1Vq+CA9HNcMSKNn2+tW6qt"));
        BigInteger rsaPubExp = new BigInteger(Base64.decode("EQ=="));
        BigInteger rsaPrivMod = new BigInteger(Base64.decode("AIASoe2PQb1IP7bTyC9usjHP7FvnUMVpKW49iuFtrw/dMpYlsMMoIU2jupfifDpdFxIktSB4P+6Ymg5WjvHKTIrvQ7SR4zV4jaPTu56Ys0pZ9EDA6gb3HLjtU+8Bb1mfWM+yjKxcPDuFjwEtjGlPHg1Vq+CA9HNcMSKNn2+tW6qt"));
        BigInteger rsaPrivDP = new BigInteger(Base64.decode("JXzfzG5v+HtLJIZqYMUefJfFLu8DPuJGaLD6lI3cZ0babWZ/oPGoJa5iHpX4Ul/7l3s1PFsuy1GhzCdOdlfRcQ=="));
        BigInteger rsaPrivDQ = new BigInteger(Base64.decode("YNdJhw3cn0gBoVmMIFRZzflPDNthBiWy/dUMSRfJCxoZjSnr1gysZHK01HteV1YYNGcwPdr3j4FbOfri5c6DUQ=="));
        BigInteger rsaPrivExp = new BigInteger(Base64.decode("DxFAOhDajr00rBjqX+7nyZ/9sHWRCCp9WEN5wCsFiWVRPtdB+NeLcou7mWXwf1Y+8xNgmmh//fPV45G2dsyBeZbXeJwB7bzx9NMEAfedchyOwjR8PYdjK3NpTLKtZlEJ6Jkh4QihrXpZMO4fKZWUm9bid3+lmiq43FwW+Hof8/E="));
        BigInteger rsaPrivP = new BigInteger(Base64.decode("AJ9StyTVW+AL/1s7RBtFwZGFBgd3zctBqzzwKPda6LbtIFDznmwDCqAlIQH9X14X7UPLokCDhuAa76OnDXb1OiE="));
        BigInteger rsaPrivQ = new BigInteger(Base64.decode("AM3JfD79dNJ5A3beScSzPtWxx/tSLi0QHFtkuhtSizeXdkv5FSba7lVzwEOGKHmW829bRoNxThDy4ds1IihW1w0="));
        BigInteger rsaPrivQinv = new BigInteger(Base64.decode("Lt0g7wrsNsQxuDdB8q/rH8fSFeBXMGLtCIqfOec1j7FEIuYA/ACiRDgXkHa0WgN7nLXSjHoy630wC5Toq8vvUg=="));
        RSAKeyParameters rsaPublic = new RSAKeyParameters(false, rsaPubMod, rsaPubExp);
        RSAPrivateCrtKeyParameters rsaPrivate = new RSAPrivateCrtKeyParameters(rsaPrivMod, rsaPubExp, rsaPrivExp, rsaPrivP, rsaPrivQ, rsaPrivDP, rsaPrivDQ, rsaPrivQinv);

        byte[] msg = new byte[] { 1, 6, 3, 32, 7, 43, 2, 5, 7, 78, 4, 23 };

        X931Signer signer = new X931Signer(new RSAEngine(), new SHA1Digest());
        signer.init(true, rsaPrivate);
        signer.update(msg, 0, msg.length);
        byte[] sig = signer.generateSignature();

        signer = new X931Signer(new RSAEngine(), new SHA1Digest());
        signer.init(false, rsaPublic);
        signer.update(msg, 0, msg.length);
        if (!signer.verifySignature(sig))
        {
            fail("X9.31 Signer failed.");
        }

        shouldPassSignatureTest1();
        shouldPassSignatureTest2();
        shouldPassSignatureTest3();
    }

    private void shouldPassSignatureTest1()
        throws Exception
    {
        BigInteger n = new BigInteger("c9be1b28f8caccca65d86cc3c9bbcc13eccc059df3b80bd2292b811eff3aa0dd75e1e85c333b8e3fa9bed53bb20f5359ff4e6900c5e9a388e3a4772a583a79e2299c76582c2b27694b65e9ba22e66bfb817f8b70b22206d7d8ae488c86dbb7137c26d5eff9b33c90e6cee640630313b7a715802e15142fef498c404a8de19674974785f0f852e2d470fe85a2e54ffca9f5851f672b71df691785a5cdabe8f14aa628942147de7593b2cf962414a5b59c632c4e14f1768c0ab2e9250824beea60a3529f11bf5e070ce90a47686eb0be1086fb21f0827f55295b4a48307db0b048c05a4aec3f488c576ca6f1879d354224c7e84cbcd8e76dd217a3de54dba73c35", 16);
        BigInteger e = new BigInteger("e75b1b", 16);
        byte[] msg = Hex.decode("5bb0d1c0ef9b5c7af2477fe08d45523d3842a4b2db943f7033126c2a7829bacb3d2cfc6497ec91688189e81b7f8742488224ba320ce983ce9480722f2cc5bc42611f00bb6311884f660ccc244788378673532edb05284fd92e83f6f6dab406209032e6af9a33c998677933e32d6fb95fd27408940d7728f9c9c40267ca1d20ce");
        byte[] sig = Hex.decode("0fe8bb8e3109a1eb7489ef35bf4c1a0780071da789c8bd226a4170538eafefdd30b732d628f0e87a0b9450051feae9754d4fb61f57862d10f0bacc4f660d13281d0cd1141c006ade5186ff7d961a4c6cd0a4b352fc1295c5afd088f80ac1f8e192ef116a010a442655fe8ff5eeacea15807906fb0f0dfa86e680d4c005872357f7ece9aa4e20b15d5f709b30f08648ecaa34f2fbf54eb6b414fa2ff6f87561f70163235e69ccb4ac82a2e46d3be214cc2ef5263b569b2d8fd839b21a9e102665105ea762bda25bb446cfd831487a6b846100dee113ae95ae64f4af22c428c87bab809541c962bb3a56d4c86588e0af4ebc7fcc66dadced311051356d3ea745f7");

        RSAKeyParameters rsaPublic = new RSAKeyParameters(false, n, e);
        X931Signer signer = new X931Signer(new RSAEngine(), new SHA1Digest());

        signer.init(false, rsaPublic);

        signer.update(msg, 0, msg.length);

        if (!signer.verifySignature(sig))
        {
            fail("RSA X931 verify test 1 failed.");
        }
    }

    private void shouldPassSignatureTest2()
        throws Exception
    {
        BigInteger n = new BigInteger("b746ba6c3c0be64bbe33aa55b2929b0af4e86d773d44bfe5914db9287788c4663984b61a418d2eecca30d752ff6b620a07ec72eeb2b422d2429da352407b99982800b9dd7697be6a7b1baa98ca5f4fc2fe33400f20b9dba337ac25c987804165d4a6e0ee4d18eabd6de5abdfe578cae6713ff91d16c80a5bb20217fe614d9509e75a43e1825327b9da8f0a9f6eeaa1c04b69fb4bacc073569fff4ab491becbe6d0441d437fc3fa823239c4a0f75321666b68dd3f66e2dd394089a15bcc288a68a4eb0a48e17d639743b9dea0a91cc35820544732aff253f8ca9967c609dc01c2f8cd0313a7a91cfa94ff74289a1d2b6f19d1811f4b9a65f4cce9e5759b4cc64f", 16);
        BigInteger e = new BigInteger("dcbbdb", 16);
        byte[] msg = Hex.decode("a5d3c8a060f897bbbc20ae0955052f37fbc70986b6e11c65075c9f457142bfa93856897c69020aa81a91b5e4f39e05cdeecc63395ab849c8262ca8bc5c96870aecb8edb0aba0024a9bdb71e06de6100344e5c318bc979ef32b8a49a8278ba99d4861bce42ebbc5c8c666aaa6cac39aff8779f2cae367620f9edd4cb1d80b6c8c");
        byte[] sig = Hex.decode("39fbbd1804c689a533b0043f84da0f06081038c0fbf31e443e46a05e58f50de5198bbca40522afefaba3aed7082a6cb93b1da39f1f5a42246bf64930781948d300549bef0f8d554ecfca60a1b1ecba95a7014ee4545ad4f0c4e3a31942c6738b4ccd6244b6a21267dadf0826a5f713f13b1f5a9ab8501d957a26d4948278ac67851071a315674bdab173bfef2c2690c8373da6bf3d69f30c0e5da8883de872f59521b40793854085641adf98d13db991c5d0a8aaa0222934fa33332e90ef0b954e195cb267d6ffb36c96e14d1ec7b915a87598b4461a3146566354dc2ae748c84ee0cd46543b53ebff8cdf47725b280a1f799fb6ebb4a31ad2bdd5178250f83a");

        RSAKeyParameters rsaPublic = new RSAKeyParameters(false, n, e);
        X931Signer signer = new X931Signer(new RSAEngine(), new SHA224Digest());

        signer.init(false, rsaPublic);

        signer.update(msg, 0, msg.length);

        if (!signer.verifySignature(sig))
        {
            fail("RSA X931 verify test 2 failed.");
        }
    }

    private void shouldPassSignatureTest3()
        throws Exception
    {
        BigInteger n = new BigInteger("dcb5686a3d2063a3f9cf7b9b32d2d3765b4c449b09b4960245a9111cd3b0cbd3260496885b8e1fa5db33b03efcc759d9c1afe29d93c6faebc7e0efada334b5b9a29655e2da2c8f11103d8203be311feab7ae88e9f1b2ec7d8fc655d77202b1681dd9717ec0f525b35584987e19539635a1ed23ca482a00149c609a23dc1645fd", 16);
        BigInteger e = new BigInteger("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000dc9f7", 16);
        BigInteger d = new BigInteger("189d6345099098992e0c9ca5f281e1338092342fa0acc85cc2a111f30f9bd2fb4753cd1a48ef0ddca9bf1af33ec76fb2e23a9fb4896c26f2235b516f7c05ef7ae81e70f4b491a5fedba9b935e9c76d761a813ce7776ff8a1e5efe1166ff2eca26aa900da88c908d51af9de26977fe39719cc781df32216fa41b838f0c63803c3", 16);

        byte[] msg = Hex.decode("911475c6e210ef4ac65b6fe8d2bfe5e01b959771b137c4ef69b88716e0d2ff9ebc1fad0f358c1dd7d50cc99a7b893ac9a6207076f08d8467d9e48c69c683bfe64a44dabaa3f7c243880f6ab7229bf7bb587822314fc5de5131983bfb2eef8b4bc1eac36f353724b567cd1ae8cddd64ddb7057549d5c81ad5fa3b5e751f00abf5");
        byte[] sig = Hex.decode("02c50ec0ac8a7f38ef5630c396964d6a6daaa7e3083ab5b57fa2a2632f3b70e2e85c8456cd774d45d7e44fcb063f0f04fff9f1e3adfda11272535a92cb59320b190b5ee4261f23d6ceaa925df3a7bfa42e26bf61ea9645d9d64b3c90a820802768a6e209c9f83705375a3867afccc037e8242a98fa4c3db6b2d9877754d47289");

        RSAKeyParameters rsaPublic = new RSAKeyParameters(false, n, e);
        X931Signer signer = new X931Signer(new RSAEngine(), new SHA1Digest());

        signer.init(true, new RSAKeyParameters(true, n, d));

        signer.update(msg, 0, msg.length);

        byte[] s = signer.generateSignature();

        if (!Arrays.areEqual(sig, s))
        {
            fail("RSA X931 sig test 3 failed.");
        }

        signer.init(false, rsaPublic);

        signer.update(msg, 0, msg.length);

        if (!signer.verifySignature(sig))
        {
            fail("RSA X931 verify test 3 failed.");
        }
    }

    public static void main(String[] args)
    {
        runTest(new X931SignerTest());
    }
}
