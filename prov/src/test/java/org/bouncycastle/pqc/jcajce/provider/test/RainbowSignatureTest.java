package org.bouncycastle.pqc.jcajce.provider.test;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;

import junit.framework.TestCase;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.RainbowParameterSpec;
import org.bouncycastle.util.encoders.Hex;

/**
 * Test cases for the use of Rainbow with the BCPQC provider.
 */
public class RainbowSignatureTest
    extends TestCase
{

    protected KeyPairGenerator kpg;

    protected Signature sig;

    private Signature sigVerify;

    private KeyPair keyPair;

    private PublicKey pubKey;

    private PrivateKey privKey;

    private byte[] mBytes;

    private byte[] sigBytes;

    private boolean valid;

    Random rand = new Random();

    private KeyFactory kf;


    public void setUp()
    {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    /**
     * Test signature generation and verification
     *
     * @param numPassesKPG    the number of key pair generation passes
     * @param numPassesSigVer the number of sign/verify passes
     * @param kpgParams       the parameters for the key pair generator
     */
    protected final void performSignVerifyTest(int numPassesKPG,
                                               int numPassesSigVer, AlgorithmParameterSpec kpgParams)
        throws Exception
    {
        this.performSignVerifyTest(numPassesKPG, numPassesSigVer,
            kpgParams, 100);
    }

    /**
     * Test signature generation and verification
     *
     * @param numPassesKPG    the number of key pair generation passes
     * @param numPassesSigVer the number of sign/verify passes
     * @param kpgParams       the parameters for the key pair generator
     * @param messageSize     length of the messages which are signed in bytes
     */
    protected final void performSignVerifyTest(int numPassesKPG,
                                               int numPassesSigVer, AlgorithmParameterSpec kpgParams,
                                               int messageSize)
        throws Exception
    {
        // generate new signature instance for verification
        //            sigVerify = (Signature) sig.getClass().newInstance();
        sigVerify = Signature.getInstance("SHA384withRainbow", "BCPQC");

        for (int j = 0; j < numPassesKPG; j++)
        {
            // generate key pair
            if (kpgParams != null)
            {
                kpg.initialize(kpgParams);
            }
            keyPair = kpg.genKeyPair();
            pubKey = keyPair.getPublic();
            privKey = keyPair.getPrivate();

            // initialize signature instances
            sig.initSign(privKey);
            sigVerify.initVerify(pubKey);

            for (int k = 1; k <= numPassesSigVer; k++)
            {
                // generate random message
                mBytes = new byte[messageSize];
                rand.nextBytes(mBytes);

                // sign
                sig.update(mBytes);
                sigBytes = sig.sign();

                // verify
                sigVerify.update(mBytes);
                valid = sigVerify.verify(sigBytes);

                // compare
                assertTrue(
                    "Signature generation and verification test failed.\n"
                        + "Message: \""
                        + new String(Hex.encode(mBytes)) + "\"\n"
                        + privKey + "\n" + pubKey, valid);
            }
        }
    }

    /**
     * Test signature generation and verification
     *
     * @param numPassesKPG    the number of key pair generation passes
     * @param numPassesSigVer the number of sign/verify passes
     * @param keySize         the key size for the key pair generator
     */
    protected final void performSignVerifyTest(int numPassesKPG,
                                               int numPassesSigVer, int keySize)
        throws Exception
    {
        for (int j = 0; j < numPassesKPG; j++)
        {
            // generate key pair

            kpg.initialize(keySize);
            keyPair = kpg.genKeyPair();
            pubKey = keyPair.getPublic();
            //writeKey("RainbowPubKey", pubKey);
            privKey = keyPair.getPrivate();
            // it causes errors! cause RainbowParameters will be null
            //pubKey = getPublicKey("RainbowPubKey");

            // initialize signature instances
            sig.initSign(privKey, new SecureRandom());
            sigVerify.initVerify(pubKey);

            for (int k = 1; k <= numPassesSigVer; k++)
            {
                // generate random message
                final int messageSize = 100;
                mBytes = new byte[messageSize];
                rand.nextBytes(mBytes);

                sig.update(mBytes, 0, mBytes.length);
                sigBytes = sig.sign();

                // verify
                sigVerify.update(mBytes, 0, mBytes.length);
                valid = sigVerify.verify(sigBytes);

                // compare
                assertTrue(
                    "Signature generation and verification test failed.\n"
                        + "Message: \""
                        + new String(Hex.encode(mBytes)) + "\"\n"
                        + privKey + "\n" + pubKey, valid);
            }
        }

    }

    /**
     * Using ParameterSpecs to initialize the key pair generator without initialization.
     */

    public void testRainbowWithSHA224()
        throws Exception
    {
        kpg = KeyPairGenerator.getInstance("Rainbow", BouncyCastlePQCProvider.PROVIDER_NAME);
        sig = Signature.getInstance("SHA224WITHRainbow", BouncyCastlePQCProvider.PROVIDER_NAME);
        sigVerify = Signature.getInstance("SHA224WITHRainbow", BouncyCastlePQCProvider.PROVIDER_NAME);
        performSignVerifyTest(1, 1, 28);
    }

    public void testRainbowithSHA256()
        throws Exception
    {
        kpg = KeyPairGenerator.getInstance("Rainbow");
        sig = Signature.getInstance("SHA256WITHRainbow");
        sigVerify = Signature.getInstance("SHA256WITHRainbow");
        performSignVerifyTest(1, 1, 32);
    }

    public void testRainbowWithSHA384()
        throws Exception
    {
        kpg = KeyPairGenerator.getInstance("Rainbow");
        sig = Signature.getInstance("SHA384WITHRainbow");
        sigVerify = Signature.getInstance("SHA384WITHRainbow");
        performSignVerifyTest(1, 1, 48);
    }

    public void testRainbowWithSHA512()
        throws Exception
    {
        kpg = KeyPairGenerator.getInstance("Rainbow");
        sig = Signature.getInstance("SHA512WITHRainbow");
        sigVerify = Signature.getInstance("SHA512WITHRainbow");
        performSignVerifyTest(1, 1, 64);
    }

    public void test_KeyFactory()
        throws Exception
    {
        kpg = KeyPairGenerator.getInstance("Rainbow");

        KeyFactory kf = KeyFactory.getInstance("Rainbow");

        AlgorithmParameterSpec specs = new RainbowParameterSpec();
        try
        {
            kpg.initialize(specs);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            e.printStackTrace();
        }
        // XXX
        kpg.initialize(5);
        keyPair = kpg.genKeyPair();
        pubKey = keyPair.getPublic();
        privKey = keyPair.getPrivate();

        byte[] pubKeyBytes = pubKey.getEncoded();
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeyBytes);
        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privKey.getEncoded());

        PublicKey publicKeyKF = kf.generatePublic(pubKeySpec);

        assertEquals(pubKey, publicKeyKF);
        assertEquals(pubKey.hashCode(), publicKeyKF.hashCode());

        PrivateKey privKeyKF = kf.generatePrivate(privKeySpec);

        assertEquals(privKey, privKeyKF);
        assertEquals(privKey.hashCode(), privKeyKF.hashCode());
    }

    public void testSignVerifyWithRandomParams()
        throws Exception
    {
        kpg = KeyPairGenerator.getInstance("Rainbow");
        sig = Signature.getInstance("SHA384WITHRainbow");
        int[] vi;

        for (int kgen = 1; kgen <= 10; kgen++)
        {
            vi = chooseRandomParams();
            RainbowParameterSpec rbParams = new RainbowParameterSpec(vi);
            performSignVerifyTest(1, 100, rbParams);
        }
    }


    /**
     * build up the set of vinegars per layer (vi)
     *
     * @return parameters vi
     */
    private int[] chooseRandomParams()
    {
        int n = rand.nextInt(10) + 2;
        int[] vi = new int[n];

        vi[0] = rand.nextInt(10) + 2;
        for (int i = 1; i < n; i++)
        {
            vi[i] = vi[i - 1];
            vi[i] += rand.nextInt(10) + 1;
        }
        return vi;
    }

    /*
     public void testSignVerifyWithSpecialParams() throws Exception {
         kpg = KeyPairGenerator.getInstance("RainbowWithSHA384");
         sig = Signature.getInstance("SHA384WITHRainbow");
         int[] vi = { 3, 20, 25, 30, 40, 60, 80, 100 };
         performSignVerifyTest(10, 200, new RainbowParameterSpec(vi));
     }
     */

    public void testSignVerifyWithDefaultParams()
        throws Exception
    {
        kpg = KeyPairGenerator.getInstance("Rainbow");
        sig = Signature.getInstance("SHA384WITHRainbow");
        performSignVerifyTest(15, 100, new RainbowParameterSpec());
    }

    public PublicKey getPublicKey(String file)
        throws Exception
    {
        kf = KeyFactory.getInstance("Rainbow");
        byte[] pubKeyBytes = getBytesFromFile(new File(file));
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeyBytes);
        return kf.generatePublic(pubKeySpec);
    }


    public byte[] getBytesFromFile(File file)
        throws IOException
    {
        InputStream is = new FileInputStream(file);

        // Get the size of the file
        long length = file.length();

        // You cannot create an array using a long type.
        // It needs to be an int type.
        // Before converting to an int type, check
        // to ensure that file is not larger than Integer.MAX_VALUE.
        if (length > Integer.MAX_VALUE)
        {
            // File is too large
        }

        // Create the byte array to hold the data
        byte[] bytes = new byte[(int)length];

        // Read in the bytes
        int offset = 0;
        int numRead = 0;
        while (offset < bytes.length
            && (numRead = is.read(bytes, offset, bytes.length - offset)) >= 0)
        {
            offset += numRead;
        }

        // Ensure all the bytes have been read in
        if (offset < bytes.length)
        {
            throw new IOException("Could not completely read file " + file.getName());
        }

        // Close the input stream and return bytes
        is.close();
        return bytes;
    }

}

