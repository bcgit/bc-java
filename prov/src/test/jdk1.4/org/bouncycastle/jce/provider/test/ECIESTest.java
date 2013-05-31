package org.bouncycastle.jce.provider.test;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.IEKeySpec;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 * test for ECIES - Elliptic Curve Integrated Encryption Scheme
 */
public class ECIESTest
    implements Test
{
    ECIESTest()
    {
    }

    public String getName()
    {
        return "ECIES";
    }

    private boolean sameAs(
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

    public TestResult perform()
    {
        TestResult  res;

        try 
        {
            KeyPairGenerator    g = KeyPairGenerator.getInstance("ECIES", "BC");

            ECCurve curve = new ECCurve.Fp(
                    new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"), // q
                    new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
                    new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b

            ECParameterSpec ecSpec = new ECParameterSpec(
                    curve,
                    curve.decodePoint(Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
                    new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307")); // n

            g.initialize(ecSpec, new SecureRandom());

            res = performTest(g);
            if (!res.isSuccessful())
            {
                return res;
            }

            g = KeyPairGenerator.getInstance("ECIES", "BC");

            g.initialize(192, new SecureRandom());

            res = performTest(g);
            if (!res.isSuccessful())
            {
                return res;
            }

            g = KeyPairGenerator.getInstance("ECIES", "BC");

            g.initialize(239, new SecureRandom());

            res = performTest(g);
            if (!res.isSuccessful())
            {
                return res;
            }

            g = KeyPairGenerator.getInstance("ECIES", "BC");

            g.initialize(256, new SecureRandom());

            res = performTest(g);
            if (!res.isSuccessful())
            {
                return res;
            }

            res = performDefTest(g);
            if (!res.isSuccessful())
            {
                return res;
            }
        }
        catch (Exception ex)
        {
            return new SimpleTestResult(false, this.getName() + ": stream cipher test exception " + ex.toString());
        }

        return new SimpleTestResult(true, this.getName() + ": Okay");
    }

    public TestResult performTest(
        KeyPairGenerator    g)
    {
        try 
        {
            //
            // a side
            //
            KeyPair     aKeyPair = g.generateKeyPair();
            PublicKey   aPub = aKeyPair.getPublic();
            PrivateKey  aPriv = aKeyPair.getPrivate();

            //
            // b side
            //
            KeyPair     bKeyPair = g.generateKeyPair();
            PublicKey   bPub = bKeyPair.getPublic();
            PrivateKey  bPriv = bKeyPair.getPrivate();

            //
            // stream test
            //
            Cipher c1 = Cipher.getInstance("ECIES", "BC");
            Cipher c2 = Cipher.getInstance("ECIES", "BC");

            IEKeySpec   c1Key = new IEKeySpec(aPriv, bPub);
            IEKeySpec   c2Key = new IEKeySpec(bPriv, aPub);

            byte[]  d = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            byte[]  e = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 };

            IESParameterSpec param = new IESParameterSpec(d, e, 128);

            c1.init(Cipher.ENCRYPT_MODE, c1Key, param);

            c2.init(Cipher.DECRYPT_MODE, c2Key, param);

            byte[] message = Hex.decode("1234567890abcdef");

            byte[]   out1 = c1.doFinal(message, 0, message.length);

            byte[]   out2 = c2.doFinal(out1, 0, out1.length);

            if (!sameAs(out2, message))
            {
                return new SimpleTestResult(false, this.getName() + ": stream cipher test failed");
            }
        }
        catch (Exception ex)
        {
            return new SimpleTestResult(false, this.getName() + ": stream cipher test exception " + ex.toString());
        }

        return new SimpleTestResult(true, this.getName() + ": Okay");
    }

    public TestResult performDefTest(
        KeyPairGenerator    g)
    {
        try 
        {
            //
            // a side
            //
            KeyPair     aKeyPair = g.generateKeyPair();
            PublicKey   aPub = aKeyPair.getPublic();
            PrivateKey  aPriv = aKeyPair.getPrivate();

            //
            // b side
            //
            KeyPair     bKeyPair = g.generateKeyPair();
            PublicKey   bPub = bKeyPair.getPublic();
            PrivateKey  bPriv = bKeyPair.getPrivate();

            //
            // stream test
            //
            Cipher c1 = Cipher.getInstance("ECIES", "BC");
            Cipher c2 = Cipher.getInstance("ECIES", "BC");

            IEKeySpec   c1Key = new IEKeySpec(aPriv, bPub);
            IEKeySpec   c2Key = new IEKeySpec(bPriv, aPub);

            c1.init(Cipher.ENCRYPT_MODE, c1Key);

            AlgorithmParameters param = c1.getParameters();

            c2.init(Cipher.DECRYPT_MODE, c2Key, param);

            byte[] message = Hex.decode("1234567890abcdef");

            byte[]   out1 = c1.doFinal(message, 0, message.length);

            byte[]   out2 = c2.doFinal(out1, 0, out1.length);

            if (!sameAs(out2, message))
            {
                return new SimpleTestResult(false, this.getName() + ": stream cipher test failed");
            }
        }
        catch (Exception ex)
        {
            return new SimpleTestResult(false, this.getName() + ": stream cipher test exception " + ex.toString());
        }

        return new SimpleTestResult(true, this.getName() + ": Okay");
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        ECIESTest    test = new ECIESTest();
        TestResult   result = test.perform();

        System.out.println(result);
    }
}
