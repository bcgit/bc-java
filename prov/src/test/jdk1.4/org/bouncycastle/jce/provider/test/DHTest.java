package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class DHTest
    implements Test
{
    private BigInteger g512 = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
    private BigInteger p512 = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);

    private BigInteger g768 = new BigInteger("7c240073c1316c621df461b71ebb0cdcc90a6e5527e5e126633d131f87461c4dc4afc60c2cb0f053b6758871489a69613e2a8b4c8acde23954c08c81cbd36132cfd64d69e4ed9f8e51ed6e516297206672d5c0a69135df0a5dcf010d289a9ca1", 16);
    private BigInteger p768 = new BigInteger("8c9dd223debed1b80103b8b309715be009d48860ed5ae9b9d5d8159508efd802e3ad4501a7f7e1cfec78844489148cd72da24b21eddd01aa624291c48393e277cfc529e37075eccef957f3616f962d15b44aeab4039d01b817fde9eaa12fd73f", 16);

    private BigInteger  g1024 = new BigInteger("1db17639cdf96bc4eabba19454f0b7e5bd4e14862889a725c96eb61048dcd676ceb303d586e30f060dbafd8a571a39c4d823982117da5cc4e0f89c77388b7a08896362429b94a18a327604eb7ff227bffbc83459ade299e57b5f77b50fb045250934938efa145511166e3197373e1b5b1e52de713eb49792bedde722c6717abf", 16);
    private BigInteger  p1024 = new BigInteger("a00e283b3c624e5b2b4d9fbc2653b5185d99499b00fd1bf244c6f0bb817b4d1c451b2958d62a0f8a38caef059fb5ecd25d75ed9af403f5b5bdab97a642902f824e3c13789fed95fa106ddfe0ff4a707c85e2eb77d49e68f2808bcea18ce128b178cd287c6bc00efa9a1ad2a673fe0dceace53166f75b81d6709d5f8af7c66bb7", 16);

    public String getName()
    {
        return "DH";
    }

    private TestResult testGP(
        int         size,
        BigInteger  g,
        BigInteger  p)
    {
        DHParameterSpec             dhParams = new DHParameterSpec(p, g);

        try
        {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");

            keyGen.initialize(dhParams);

            //
            // a side
            //
            KeyPair aKeyPair = keyGen.generateKeyPair();
    
            KeyAgreement aKeyAgree = KeyAgreement.getInstance("DH", "BC");

            aKeyAgree.init(aKeyPair.getPrivate());

            //
            // b side
            //
            KeyPair bKeyPair = keyGen.generateKeyPair();

            KeyAgreement bKeyAgree = KeyAgreement.getInstance("DH", "BC");

            bKeyAgree.init(bKeyPair.getPrivate());

            //
            // agreement
            //
            aKeyAgree.doPhase(bKeyPair.getPublic(), true);
            bKeyAgree.doPhase(aKeyPair.getPublic(), true);

            BigInteger  k1 = new BigInteger(aKeyAgree.generateSecret());
            BigInteger  k2 = new BigInteger(bKeyAgree.generateSecret());

            if (!k1.equals(k2))
            {
                return new SimpleTestResult(false, size + " bit 2-way test failed");
            }

            //
            // public key encoding test
            //
            byte[]              pubEnc = aKeyPair.getPublic().getEncoded();
            KeyFactory          keyFac = KeyFactory.getInstance("DH", "BC");
            X509EncodedKeySpec  pubX509 = new X509EncodedKeySpec(pubEnc);
            DHPublicKey         pubKey = (DHPublicKey)keyFac.generatePublic(pubX509);
            DHParameterSpec     spec = pubKey.getParams();

            if (!spec.getG().equals(dhParams.getG()) || !spec.getP().equals(dhParams.getP()))
            {
                return new SimpleTestResult(false, size + " bit public key encoding/decoding test failed on parameters");
            }

            if (!((DHPublicKey)aKeyPair.getPublic()).getY().equals(pubKey.getY()))
            {
                return new SimpleTestResult(false, size + " bit public key encoding/decoding test failed on y value");
            }

            //
            // public key serialisation test
            //
            ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
            ObjectOutputStream      oOut = new ObjectOutputStream(bOut);

            oOut.writeObject(aKeyPair.getPublic());

            ByteArrayInputStream   bIn = new ByteArrayInputStream(bOut.toByteArray());
            ObjectInputStream      oIn = new ObjectInputStream(bIn);

            pubKey = (DHPublicKey)oIn.readObject();
            spec = pubKey.getParams();

            if (!spec.getG().equals(dhParams.getG()) || !spec.getP().equals(dhParams.getP()))
            {
                return new SimpleTestResult(false, size + " bit public key serialisation test failed on parameters");
            }

            if (!((DHPublicKey)aKeyPair.getPublic()).getY().equals(pubKey.getY()))
            {
                return new SimpleTestResult(false, size + " bit public key serialisation test failed on y value");
            }

            //
            // private key encoding test
            //
            byte[]              privEnc = aKeyPair.getPrivate().getEncoded();
            PKCS8EncodedKeySpec privPKCS8 = new PKCS8EncodedKeySpec(privEnc);
            DHPrivateKey        privKey = (DHPrivateKey)keyFac.generatePrivate(privPKCS8);

            spec = privKey.getParams();

            if (!spec.getG().equals(dhParams.getG()) || !spec.getP().equals(dhParams.getP()))
            {
                return new SimpleTestResult(false, size + " bit private key encoding/decoding test failed on parameters");
            }

            if (!((DHPrivateKey)aKeyPair.getPrivate()).getX().equals(privKey.getX()))
            {
                return new SimpleTestResult(false, size + " bit private key encoding/decoding test failed on y value");
            }

            //
            // private key serialisation test
            //
            bOut = new ByteArrayOutputStream();
            oOut = new ObjectOutputStream(bOut);

            oOut.writeObject(aKeyPair.getPrivate());

            bIn = new ByteArrayInputStream(bOut.toByteArray());
            oIn = new ObjectInputStream(bIn);

            privKey = (DHPrivateKey)oIn.readObject();
            spec = privKey.getParams();

            if (!spec.getG().equals(dhParams.getG()) || !spec.getP().equals(dhParams.getP()))
            {
                return new SimpleTestResult(false, size + " bit private key serialisation test failed on parameters");
            }

            if (!((DHPrivateKey)aKeyPair.getPrivate()).getX().equals(privKey.getX()))
            {
                return new SimpleTestResult(false, size + " bit private key serialisation test failed on y value");
            }

            //
            // three party test
            //
            KeyPairGenerator aPairGen = KeyPairGenerator.getInstance("DH", "BC");
            aPairGen.initialize(spec);
            KeyPair aPair = aPairGen.generateKeyPair();

            KeyPairGenerator bPairGen = KeyPairGenerator.getInstance("DH", "BC");
            bPairGen.initialize(spec);
            KeyPair bPair = bPairGen.generateKeyPair();

            KeyPairGenerator cPairGen = KeyPairGenerator.getInstance("DH", "BC");
            cPairGen.initialize(spec);
            KeyPair cPair = cPairGen.generateKeyPair();

            aKeyAgree.init(aPair.getPrivate());

            bKeyAgree.init(bPair.getPrivate());

            KeyAgreement cKeyAgree = KeyAgreement.getInstance("DH", "BC");
            cKeyAgree.init(cPair.getPrivate());

            Key ac = aKeyAgree.doPhase(cPair.getPublic(), false);

            Key ba = bKeyAgree.doPhase(aPair.getPublic(), false);

            Key cb = cKeyAgree.doPhase(bPair.getPublic(), false);

            aKeyAgree.doPhase(cb, true);

            bKeyAgree.doPhase(ac, true);

            cKeyAgree.doPhase(ba, true);

            BigInteger aShared = new BigInteger(aKeyAgree.generateSecret());
            BigInteger bShared = new BigInteger(bKeyAgree.generateSecret());
            BigInteger cShared = new BigInteger(cKeyAgree.generateSecret());

            if (!aShared.equals(bShared))
            {
                return new SimpleTestResult(false, size + " bit 3-way test failed (a and b differ)");
            }

            if (!cShared.equals(bShared))
            {
                return new SimpleTestResult(false, size + " bit 3-way test failed (c and b differ)");
            }
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, size + " bit 2-way test failed - exception: " + e);
        }

        return new SimpleTestResult(true, this.getName() + ": Okay");
    }

    private TestResult testRandom(
        int         size)
    {
        try
        {
            AlgorithmParameterGenerator a = AlgorithmParameterGenerator.getInstance("DH", "BC");
            a.init(size, new SecureRandom());
            AlgorithmParameters params = a.generateParameters();

            byte[] encodeParams = params.getEncoded();

            AlgorithmParameters a2 = AlgorithmParameters.getInstance("DH", "BC");
            a2.init(encodeParams);

            // a and a2 should be equivalent!
            byte[] encodeParams_2 = a2.getEncoded();

            if (!arrayEquals(encodeParams, encodeParams_2))
            {
                return new SimpleTestResult(false, this.getName() + ": encode/decode parameters failed");
            }

            DHParameterSpec dhP = (DHParameterSpec)params.getParameterSpec(DHParameterSpec.class);

            return testGP(size, dhP.getG(), dhP.getP());
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, this.getName() + ": exception - " + e.toString());
        }
    }

    private TestResult testECDH()
    {
        try
        {
            KeyPairGenerator    g = KeyPairGenerator.getInstance("ECDH", "BC");

            ECCurve curve = new ECCurve.Fp(
                    new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"), // q
                    new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
                    new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b

            ECParameterSpec ecSpec = new ECParameterSpec(
                    curve,
                    curve.decodePoint(Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
                    new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307")); // n

            g.initialize(ecSpec, new SecureRandom());

            //
            // a side
            //
            KeyPair aKeyPair = g.generateKeyPair();
    
            KeyAgreement aKeyAgree = KeyAgreement.getInstance("ECDH", "BC");

            aKeyAgree.init(aKeyPair.getPrivate());

            //
            // b side
            //
            KeyPair bKeyPair = g.generateKeyPair();

            KeyAgreement bKeyAgree = KeyAgreement.getInstance("ECDH", "BC");

            bKeyAgree.init(bKeyPair.getPrivate());

            //
            // agreement
            //
            aKeyAgree.doPhase(bKeyPair.getPublic(), true);
            bKeyAgree.doPhase(aKeyPair.getPublic(), true);

            BigInteger  k1 = new BigInteger(aKeyAgree.generateSecret());
            BigInteger  k2 = new BigInteger(bKeyAgree.generateSecret());

            if (!k1.equals(k2))
            {
                return new SimpleTestResult(false, "ECDH 2-way test failed");
            }

            //
            // public key encoding test
            //
            byte[]              pubEnc = aKeyPair.getPublic().getEncoded();
            KeyFactory          keyFac = KeyFactory.getInstance("ECDH", "BC");
            X509EncodedKeySpec  pubX509 = new X509EncodedKeySpec(pubEnc);
            ECPublicKey         pubKey = (ECPublicKey)keyFac.generatePublic(pubX509);

            if (!pubKey.getQ().equals(((ECPublicKey)aKeyPair.getPublic()).getQ()))
            {
                return new SimpleTestResult(false, "ECDH public key encoding (Q test) failed");
            }

            if (!pubKey.getParameters().getG().equals(((ECPublicKey)aKeyPair.getPublic()).getParameters().getG()))
            {
                return new SimpleTestResult(false, "ECDH public key encoding (G test) failed");
            }

            //
            // private key encoding test
            //
            byte[]              privEnc = aKeyPair.getPrivate().getEncoded();
            PKCS8EncodedKeySpec privPKCS8 = new PKCS8EncodedKeySpec(privEnc);
            ECPrivateKey        privKey = (ECPrivateKey)keyFac.generatePrivate(privPKCS8);

            if (!privKey.getD().equals(((ECPrivateKey)aKeyPair.getPrivate()).getD()))
            {
                return new SimpleTestResult(false, "ECDH private key encoding (D test) failed");
            }

            if (!privKey.getParameters().getG().equals(((ECPrivateKey)aKeyPair.getPrivate()).getParameters().getG()))
            {
                return new SimpleTestResult(false, "ECDH private key encoding (G test) failed");
            }
        }
        catch (Exception e)
        {
                return new SimpleTestResult(false, "ECDH 2-way test failed - exception: " + e);
        }

        return new SimpleTestResult(true, this.getName() + ": Okay");
    }

    private TestResult testECDHC()
    {
        try
        {
            KeyPairGenerator    g = KeyPairGenerator.getInstance("ECDH", "BC");

            ECCurve curve = new ECCurve.Fp(
                    new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"), // q
                    new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
                    new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b

            ECParameterSpec ecSpec = new ECParameterSpec(
                    curve,
                    curve.decodePoint(Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
                    new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307")); // n

            g.initialize(ecSpec, new SecureRandom());

            //
            // a side
            //
            KeyPair aKeyPair = g.generateKeyPair();
    
            KeyAgreement aKeyAgree = KeyAgreement.getInstance("ECDHC", "BC");

            aKeyAgree.init(aKeyPair.getPrivate());

            //
            // b side
            //
            KeyPair bKeyPair = g.generateKeyPair();

            KeyAgreement bKeyAgree = KeyAgreement.getInstance("ECDHC", "BC");

            bKeyAgree.init(bKeyPair.getPrivate());

            //
            // agreement
            //
            aKeyAgree.doPhase(bKeyPair.getPublic(), true);
            bKeyAgree.doPhase(aKeyPair.getPublic(), true);

            BigInteger  k1 = new BigInteger(aKeyAgree.generateSecret());
            BigInteger  k2 = new BigInteger(bKeyAgree.generateSecret());

            if (!k1.equals(k2))
            {
                return new SimpleTestResult(false, "ECDHC 2-way test failed");
            }

            //
            // public key encoding test
            //
            byte[]              pubEnc = aKeyPair.getPublic().getEncoded();
            KeyFactory          keyFac = KeyFactory.getInstance("ECDH", "BC");
            X509EncodedKeySpec  pubX509 = new X509EncodedKeySpec(pubEnc);
            ECPublicKey         pubKey = (ECPublicKey)keyFac.generatePublic(pubX509);

            if (!pubKey.getQ().equals(((ECPublicKey)aKeyPair.getPublic()).getQ()))
            {
                return new SimpleTestResult(false, "ECDH public key encoding (Q test) failed");
            }

            if (!pubKey.getParameters().getN().equals(((ECPublicKey)aKeyPair.getPublic()).getParameters().getN()))
            {
                return new SimpleTestResult(false, "ECDH public key encoding (N test) failed");
            }

            //
            // private key encoding test
            //
            byte[]              privEnc = aKeyPair.getPrivate().getEncoded();
            PKCS8EncodedKeySpec privPKCS8 = new PKCS8EncodedKeySpec(privEnc);
            ECPrivateKey        privKey = (ECPrivateKey)keyFac.generatePrivate(privPKCS8);

            if (!privKey.getD().equals(((ECPrivateKey)aKeyPair.getPrivate()).getD()))
            {
                return new SimpleTestResult(false, "ECDH private key encoding (D test) failed");
            }

            if (!privKey.getParameters().getN().equals(((ECPrivateKey)aKeyPair.getPrivate()).getParameters().getN()))
            {
                return new SimpleTestResult(false, "ECDH private key encoding (N test) failed");
            }
        }
        catch (Exception e)
        {
                return new SimpleTestResult(false, "ECDHC 2-way test failed - exception: " + e);
        }

        return new SimpleTestResult(true, this.getName() + ": Okay");
    }

    private TestResult testExceptions()
    {
        DHParameterSpec        dhParams = new DHParameterSpec(p512, g512);

        try
        {
            KeyAgreement aKeyAgree = KeyAgreement.getInstance("DH", "BC");

            aKeyAgree.generateSecret("DES");
        }
        catch (IllegalStateException e)
        {
            // okay
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, "Unexpected exception: " + e, e);
        }

        return new SimpleTestResult(true, this.getName() + ": Okay");
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


    public TestResult perform()
    {
        TestResult      result;
  
        result = testGP(512, g512, p512);
        if (!result.isSuccessful())
        {
            return result;
        }
        
        result = testGP(768, g768, p768);
        if (!result.isSuccessful())
        {
            return result;
        }
        
        result = testGP(1024, g1024, p1024);
        if (!result.isSuccessful())
        {
            return result;
        }

        result = testRandom(256);
        if (!result.isSuccessful())
        {
            return result;
        }

        result = testECDH();
        if (!result.isSuccessful())
        {
            return result;
        }
        
        result = testECDHC();
        if (!result.isSuccessful())
        {
            return result;
        }
        
        result = testExceptions();
        if (!result.isSuccessful())
        {
            return result;
        }
        
        return result;
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        DHTest         test = new DHTest();
        TestResult      result = test.perform();

        System.out.println(result);
    }
}
