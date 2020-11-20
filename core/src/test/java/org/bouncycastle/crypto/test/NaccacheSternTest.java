package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Vector;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.NaccacheSternEngine;
import org.bouncycastle.crypto.generators.NaccacheSternKeyPairGenerator;
import org.bouncycastle.crypto.params.NaccacheSternKeyGenerationParameters;
import org.bouncycastle.crypto.params.NaccacheSternKeyParameters;
import org.bouncycastle.crypto.params.NaccacheSternPrivateKeyParameters;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Test case for NaccacheStern cipher. For details on this cipher, please see
 * 
 * https://www.gemplus.com/smart/rd/publications/pdf/NS98pkcs.pdf
 *
 * Performs the following tests: 
 *  <ul>
 *  <li> Toy example from the NaccacheSternPaper </li>
 *  <li> 768 bit test with text "Now is the time for all good men." (ripped from RSA test) and
 *     the same test with the first byte replaced by 0xFF </li>
 *  <li> 1024 bit test analog to 768 bit test </li>
 *  </ul>
 */
public class NaccacheSternTest
    extends SimpleTest
{
    static final boolean debug = false;

    static final NaccacheSternEngine cryptEng = new NaccacheSternEngine();

    static final NaccacheSternEngine decryptEng = new NaccacheSternEngine();

    // Values from NaccacheStern paper
    static final BigInteger a = BigInteger.valueOf(101);

    static final BigInteger u1 = BigInteger.valueOf(3);

    static final BigInteger u2 = BigInteger.valueOf(5);

    static final BigInteger u3 = BigInteger.valueOf(7);

    static final BigInteger b = BigInteger.valueOf(191);

    static final BigInteger v1 = BigInteger.valueOf(11);

    static final BigInteger v2 = BigInteger.valueOf(13);

    static final BigInteger v3 = BigInteger.valueOf(17);

    static final BigInteger ONE = BigInteger.valueOf(1);

    static final BigInteger TWO = BigInteger.valueOf(2);

    static final BigInteger sigma = u1.multiply(u2).multiply(u3).multiply(v1)
            .multiply(v2).multiply(v3);

    static final BigInteger p = TWO.multiply(a).multiply(u1).multiply(u2)
            .multiply(u3).add(ONE);

    static final BigInteger q = TWO.multiply(b).multiply(v1).multiply(v2)
            .multiply(v3).add(ONE);

    static final BigInteger n = p.multiply(q);

    static final BigInteger phi_n = p.subtract(ONE).multiply(q.subtract(ONE));

    static final BigInteger g = BigInteger.valueOf(131);

    static final Vector smallPrimes = new Vector();

    // static final BigInteger paperTest = BigInteger.valueOf(202);

    static final String input = "4e6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e";

    static final BigInteger paperTest = BigInteger.valueOf(202);

    //
    // to check that we handling byte extension by big number correctly.
    //
    static final String edgeInput = "ff6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e";

    static
    {
        cryptEng.setDebug(debug);
        decryptEng.setDebug(debug);

        // First the Parameters from the NaccacheStern Paper
        // (see https://www.gemplus.com/smart/rd/publications/pdf/NS98pkcs.pdf )

        smallPrimes.addElement(u1);
        smallPrimes.addElement(u2);
        smallPrimes.addElement(u3);
        smallPrimes.addElement(v1);
        smallPrimes.addElement(v2);
        smallPrimes.addElement(v3);
    }

    public String getName()
    {
        return "NaccacheStern";
    }

    public void performTest()
    {
        // Test with given key from NaccacheSternPaper (totally insecure)

        NaccacheSternKeyParameters pubParameters = new NaccacheSternKeyParameters(false, g, n, sigma.bitLength());

        NaccacheSternPrivateKeyParameters privParameters = new NaccacheSternPrivateKeyParameters(g, n, sigma.bitLength(), smallPrimes, phi_n);

        AsymmetricCipherKeyPair pair = new AsymmetricCipherKeyPair(pubParameters, privParameters);

        // Initialize Engines with KeyPair

        if (debug)
        {
            System.out.println("initializing encryption engine");
        }
        cryptEng.init(true, pair.getPublic());

        if (debug)
        {
            System.out.println("initializing decryption engine");
        }
        decryptEng.init(false, pair.getPrivate());

        byte[] data = paperTest.toByteArray();

        if (!new BigInteger(data).equals(new BigInteger(enDeCrypt(data))))
        {
            fail("failed NaccacheStern paper test");
        }

        //
        // key generation test
        //

        // 
        // 768 Bit test
        //

        if (debug)
        {
            System.out.println();
            System.out.println("768 Bit TEST");
        }

        // specify key generation parameters
        NaccacheSternKeyGenerationParameters genParam
            = new NaccacheSternKeyGenerationParameters(new SecureRandom(), 768, 8, 30, debug);

        // Initialize Key generator and generate key pair
        NaccacheSternKeyPairGenerator pGen = new NaccacheSternKeyPairGenerator();
        pGen.init(genParam);

        pair = pGen.generateKeyPair();

        if (((NaccacheSternKeyParameters)pair.getPublic()).getModulus().bitLength() < 768)
        {
            System.out.println("FAILED: key size is <786 bit, exactly "
                            + ((NaccacheSternKeyParameters)pair.getPublic()).getModulus().bitLength() + " bit");
            fail("failed key generation (768) length test");
        }

        // Initialize Engines with KeyPair

        if (debug)
        {
            System.out.println("initializing " + genParam.getStrength() + " bit encryption engine");
        }
        cryptEng.init(true, pair.getPublic());

        if (debug)
        {
            System.out.println("initializing " + genParam.getStrength() + " bit decryption engine");
        }
        decryptEng.init(false, pair.getPrivate());

        // Basic data input
        data = Hex.decode(input);

        if (!new BigInteger(1, data).equals(new BigInteger(1, enDeCrypt(data))))
        {
            fail("failed encryption decryption (" + genParam.getStrength() + ") basic test");
        }

        // Data starting with FF byte (would be interpreted as negative
        // BigInteger)

        data = Hex.decode(edgeInput);

        if (!new BigInteger(1, data).equals(new BigInteger(1, enDeCrypt(data))))
        {
            fail("failed encryption decryption (" + genParam.getStrength() + ") edgeInput test");
        }

        // 
        // 1024 Bit Test
        // 
/*
        if (debug)
        {
            System.out.println();
            System.out.println("1024 Bit TEST");
        }

        // specify key generation parameters
        genParam = new NaccacheSternKeyGenerationParameters(new SecureRandom(), 1024, 8, 40);

        pGen.init(genParam);
        pair = pGen.generateKeyPair();

        if (((NaccacheSternKeyParameters)pair.getPublic()).getModulus().bitLength() < 1024)
        {
            if (debug)
            {
                System.out.println("FAILED: key size is <1024 bit, exactly "
                                + ((NaccacheSternKeyParameters)pair.getPublic()).getModulus().bitLength() + " bit");
            }
            fail("failed key generation (1024) length test");
        }

        // Initialize Engines with KeyPair

        if (debug)
        {
            System.out.println("initializing " + genParam.getStrength() + " bit encryption engine");
        }
        cryptEng.init(true, pair.getPublic());

        if (debug)
        {
            System.out.println("initializing " + genParam.getStrength() + " bit decryption engine");
        }
        decryptEng.init(false, pair.getPrivate());

        if (debug)
        {
            System.out.println("Data is           " + new BigInteger(1, data));
        }

        // Basic data input
        data = Hex.decode(input);

        if (!new BigInteger(1, data).equals(new BigInteger(1, enDeCrypt(data))))
        {
            fail("failed encryption decryption (" + genParam.getStrength() + ") basic test");
        }

        // Data starting with FF byte (would be interpreted as negative
        // BigInteger)

        data = Hex.decode(edgeInput);

        if (!new BigInteger(1, data).equals(new BigInteger(1, enDeCrypt(data))))
        {
            fail("failed encryption decryption (" + genParam.getStrength() + ") edgeInput test");
        }
*/
        // END OF TEST CASE

        try
        {
            new NaccacheSternEngine().processBlock(new byte[]{ 1 }, 0, 1);
            fail("failed initialisation check");
        }
        catch (IllegalStateException e)
        {
            // expected
        }
        catch (InvalidCipherTextException e)
        {
            fail("failed initialisation check");
        }

        if (debug)
        {
            System.out.println("All tests successful");
        }
    }

    private byte[] enDeCrypt(byte[] input)
    {

        // create work array
        byte[] data = new byte[input.length];
        System.arraycopy(input, 0, data, 0, data.length);

        // Perform encryption like in the paper from Naccache-Stern
        if (debug)
        {
            System.out.println("encrypting data. Data representation\n"
            //                    + "As String:.... " + new String(data) + "\n"
                            + "As BigInteger: " + new BigInteger(1, data));
            System.out.println("data length is " + data.length);
        }

        try
        {
            data = cryptEng.processData(data);
        }
        catch (InvalidCipherTextException e)
        {
            if (debug)
            {
                System.out.println("failed - exception " + e.toString() + "\n" + e.getMessage());
            }
            fail("failed - exception " + e.toString() + "\n" + e.getMessage());
        }

        if (debug)
        {
            System.out.println("enrypted data representation\n"
            //                    + "As String:.... " + new String(data) + "\n"
                            + "As BigInteger: " + new BigInteger(1, data));
            System.out.println("data length is " + data.length);
        }

        try
        {
            data = decryptEng.processData(data);
        }
        catch (InvalidCipherTextException e)
        {
            if (debug)
            {
                System.out.println("failed - exception " + e.toString() + "\n" + e.getMessage());
            }
            fail("failed - exception " + e.toString() + "\n" + e.getMessage());
        }

        if (debug)
        {
            System.out.println("decrypted data representation\n"
            //                    + "As String:.... " + new String(data) + "\n"
                            + "As BigInteger: " + new BigInteger(1, data));
            System.out.println("data length is " + data.length);
        }

        return data;

    }

    public static void main(String[] args)
    {
        runTest(new NaccacheSternTest());
    }
}
