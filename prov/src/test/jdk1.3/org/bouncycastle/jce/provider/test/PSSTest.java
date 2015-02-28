package org.bouncycastle.jce.provider.test;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;


public class PSSTest
    implements Test
{
    private class FixedRandom
        extends SecureRandom
    {
        byte[]  vals;

        FixedRandom(
            byte[]  vals)
        {
            this.vals = vals;
        }

        public void nextBytes(
            byte[]  bytes)
        {
            System.arraycopy(vals, 0, bytes, 0, vals.length);
        }
    }

    private boolean arrayEquals(
        byte[]  a,
        byte[]  b)
    {
        if (a.length != b.length)
        {
            return false;
        }

        for (int i = 0; i != a.length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }

        return true;
    }


    private RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(
        new BigInteger("a56e4a0e701017589a5187dc7ea841d156f2ec0e36ad52a44dfeb1e61f7ad991d8c51056ffedb162b4c0f283a12a88a394dff526ab7291cbb307ceabfce0b1dfd5cd9508096d5b2b8b6df5d671ef6377c0921cb23c270a70e2598e6ff89d19f105acc2d3f0cb35f29280e1386b6f64c4ef22e1e1f20d0ce8cffb2249bd9a2137",16),
        new BigInteger("010001",16));

    private RSAPrivateCrtKeySpec privKeySpec = new RSAPrivateCrtKeySpec(
        new BigInteger("a56e4a0e701017589a5187dc7ea841d156f2ec0e36ad52a44dfeb1e61f7ad991d8c51056ffedb162b4c0f283a12a88a394dff526ab7291cbb307ceabfce0b1dfd5cd9508096d5b2b8b6df5d671ef6377c0921cb23c270a70e2598e6ff89d19f105acc2d3f0cb35f29280e1386b6f64c4ef22e1e1f20d0ce8cffb2249bd9a2137",16),
        new BigInteger("010001",16),
        new BigInteger("33a5042a90b27d4f5451ca9bbbd0b44771a101af884340aef9885f2a4bbe92e894a724ac3c568c8f97853ad07c0266c8c6a3ca0929f1e8f11231884429fc4d9ae55fee896a10ce707c3ed7e734e44727a39574501a532683109c2abacaba283c31b4bd2f53c3ee37e352cee34f9e503bd80c0622ad79c6dcee883547c6a3b325",16),
        new BigInteger("e7e8942720a877517273a356053ea2a1bc0c94aa72d55c6e86296b2dfc967948c0a72cbccca7eacb35706e09a1df55a1535bd9b3cc34160b3b6dcd3eda8e6443",16),
        new BigInteger("b69dca1cf7d4d7ec81e75b90fcca874abcde123fd2700180aa90479b6e48de8d67ed24f9f19d85ba275874f542cd20dc723e6963364a1f9425452b269a6799fd",16),
        new BigInteger("28fa13938655be1f8a159cbaca5a72ea190c30089e19cd274a556f36c4f6e19f554b34c077790427bbdd8dd3ede2448328f385d81b30e8e43b2fffa027861979",16),
        new BigInteger("1a8b38f398fa712049898d7fb79ee0a77668791299cdfa09efc0e507acb21ed74301ef5bfd48be455eaeb6e1678255827580a8e4e8e14151d1510a82a3f2e729",16),
        new BigInteger("27156aba4126d24a81f3a528cbfb27f56886f840a9f6e86e17a44b94fe9319584b8e22fdde1e5a2e3bd8aa5ba8d8584194eb2190acf832b847f13a3d24a79f4d",16));

    // PSSExample1.1

    private byte[] msg1a = Hex.decode("cdc87da223d786df3b45e0bbbc721326d1ee2af806cc315475cc6f0d9c66e1b62371d45ce2392e1ac92844c310102f156a0d8d52c1f4c40ba3aa65095786cb769757a6563ba958fed0bcc984e8b517a3d5f515b23b8a41e74aa867693f90dfb061a6e86dfaaee64472c00e5f20945729cbebe77f06ce78e08f4098fba41f9d6193c0317e8b60d4b6084acb42d29e3808a3bc372d85e331170fcbf7cc72d0b71c296648b3a4d10f416295d0807aa625cab2744fd9ea8fd223c42537029828bd16be02546f130fd2e33b936d2676e08aed1b73318b750a0167d0");

    private byte[] slt1a = Hex.decode("dee959c7e06411361420ff80185ed57f3e6776af");

    private byte[] sig1a = Hex.decode("9074308fb598e9701b2294388e52f971faac2b60a5145af185df5287b5ed2887e57ce7fd44dc8634e407c8e0e4360bc226f3ec227f9d9e54638e8d31f5051215df6ebb9c2f9579aa77598a38f914b5b9c1bd83c4e2f9f382a0d0aa3542ffee65984a601bc69eb28deb27dca12c82c2d4c3f66cd500f1ff2b994d8a4e30cbb33c");

    private byte[] sig1b = Hex.decode("96ea348db4db2947aee807bd687411a880913706f21b383a1002b97e43656e5450a9d1812efbedd1ed159f8307986adf48bada66a8efd14bd9e2f6f6f458e73b50c8ce6e3079011c5b4bd1600a2601a66198a1582574a43f13e0966c6c2337e6ca0886cd9e1b1037aeadef1382117d22b35e7e4403f90531c8cfccdf223f98e4");

    public TestResult perform()
    {
        try
        {
            KeyFactory fact = KeyFactory.getInstance("RSA", "BC");

            PrivateKey  privKey = fact.generatePrivate(privKeySpec);
            PublicKey   pubKey = fact.generatePublic(pubKeySpec);

            Signature s = Signature.getInstance("SHA1withRSA/PSS", "BC");

            s.initSign(privKey, new FixedRandom(slt1a));
            s.update(msg1a);
            byte[] sig = s.sign();

            if (!arrayEquals(sig1a, sig))
            {
                return new SimpleTestResult(false, "PSS Sign test expected " + new String(Hex.encode(sig1a)) + " got " + new String(Hex.encode(sig)));
            }

            s = Signature.getInstance("SHA1withRSAandMGF1", "BC");
            
            s.initVerify(pubKey);
            s.update(msg1a);
            if (!s.verify(sig1a))
            {
                return new SimpleTestResult(false, "SHA1 signature verification failed");
            }

            s = Signature.getInstance("SHA256WithRSA/PSS", "BC");

            s.initSign(privKey, new FixedRandom(slt1a));
            s.update(msg1a);
            sig = s.sign();

            if (!arrayEquals(sig1b, sig))
            {
                return new SimpleTestResult(false, "PSS Sign test expected " + new String(Hex.encode(sig1b)) + " got " + new String(Hex.encode(sig)));
            }

            s = Signature.getInstance("SHA256withRSAandMGF1", "BC");
            
            s.initVerify(pubKey);
            s.update(msg1a);
            if (!s.verify(sig1b))
            {
                return new SimpleTestResult(false, "SHA256 signature verification failed");
            }

            return new SimpleTestResult(true, getName() + ": Okay");
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": exception - " + e.toString());
        }
    }

    public String getName()
    {
        return "PSSTest";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        Test            test = new PSSTest();
        TestResult      result = test.perform();

        System.out.println(result.toString());
    }
}
