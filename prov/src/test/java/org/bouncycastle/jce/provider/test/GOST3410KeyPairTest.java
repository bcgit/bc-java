package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTest;

public class GOST3410KeyPairTest
    extends SimpleTest
{
    private void gost2012MismatchTest()
        throws Exception
    {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance(
            "ECGOST3410-2012", "BC");

        keyPair.initialize(new ECGenParameterSpec("Tc26-Gost-3410-12-512-paramSetA"));

        KeyPair kp = keyPair.generateKeyPair();

        testWrong256(kp);

        keyPair = KeyPairGenerator.getInstance(
            "ECGOST3410-2012", "BC");

        keyPair.initialize(new ECGenParameterSpec("Tc26-Gost-3410-12-512-paramSetB"));

        kp = keyPair.generateKeyPair();

        testWrong256(kp);

        keyPair = KeyPairGenerator.getInstance(
            "ECGOST3410-2012", "BC");

        keyPair.initialize(new ECGenParameterSpec("Tc26-Gost-3410-12-512-paramSetC"));

        kp = keyPair.generateKeyPair();

        testWrong256(kp);

        keyPair = KeyPairGenerator.getInstance(
            "ECGOST3410-2012", "BC");

        keyPair.initialize(new ECGenParameterSpec("Tc26-Gost-3410-12-256-paramSetA"));

        kp = keyPair.generateKeyPair();

        testWrong512(kp);
    }

    private void testWrong512(KeyPair kp)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        Signature sig;
        sig = Signature.getInstance("ECGOST3410-2012-512", "BC");

        try
        {
            sig.initSign(kp.getPrivate());

            fail("no exception");
        }
        catch (InvalidKeyException e)
        {
            isEquals("key too weak for ECGOST-2012-512", e.getMessage());
        }

        try
        {
            sig.initVerify(kp.getPublic());
            fail("no exception");
        }
        catch (InvalidKeyException e)
        {
            isEquals("key too weak for ECGOST-2012-512", e.getMessage());
        }
    }

    private void testWrong256(KeyPair kp)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        Signature sig = Signature.getInstance("ECGOST3410-2012-256", "BC");

        try
        {
            sig.initSign(kp.getPrivate());
            fail("no exception");
        }
        catch (InvalidKeyException e)
        {
            isEquals("key out of range for ECGOST-2012-256", e.getMessage());
        }

        try
        {
            sig.initVerify(kp.getPublic());
            fail("no exception");
        }
        catch (InvalidKeyException e)
        {
            isEquals("key out of range for ECGOST-2012-256", e.getMessage());
        }
    }

    private BigInteger[] decode(
        byte[] encoding)
    {
        byte[] r = new byte[32];
        byte[] s = new byte[32];

        System.arraycopy(encoding, 0, s, 0, 32);

        System.arraycopy(encoding, 32, r, 0, 32);

        BigInteger[] sig = new BigInteger[2];

        sig[0] = new BigInteger(1, r);
        sig[1] = new BigInteger(1, s);

        return sig;
    }

    private Object serializeDeserialize(Object o)
        throws Exception
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(o);
        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        return oIn.readObject();
    }

    public String getName()
    {
        return "GOST3410/ECGOST3410/ECGOST3410 2012";
    }

    public void performTest()
        throws Exception
    {
        gost2012MismatchTest();
    }

    protected byte[] toByteArray(String input)
    {
        byte[] bytes = new byte[input.length()];

        for (int i = 0; i != bytes.length; i++)
        {
            bytes[i] = (byte)input.charAt(i);
        }

        return bytes;
    }

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new GOST3410KeyPairTest());
    }
}
