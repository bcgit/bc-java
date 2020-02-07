package org.bouncycastle.pqc.crypto.lms;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;
import org.bouncycastle.crypto.prng.FixedSecureRandom;
import org.bouncycastle.pqc.crypto.ExhaustedPrivateKeyException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;

public class HSSTests
    extends TestCase
{

    public void testHssKeySerialisation()
        throws Exception
    {
        byte[] fixedSource = new byte[8192];
        for (int t = 0; t < fixedSource.length; t++)
        {
            fixedSource[t] = 1;
        }

        SecureRandom rand = new FixedSecureRandom(fixedSource);

        HSSPrivateKeyParameters generatedPrivateKey = HSS.generateHSSKeyPair(
            HSSKeyGenerationParameters.builder(2)
                .setLmsParameters(
                    new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
                    new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w2))
                .setLmsEntropySource(rand)
                .build()
        );

        HSSSignature sigFromGeneratedPrivateKey = HSS.generateSignature(generatedPrivateKey, Hex.decode("ABCDEF"), rand);

        byte[] keyPairEnc = generatedPrivateKey.getEncoded();

        HSSPrivateKeyParameters reconstructedPrivateKey = HSSPrivateKeyParameters.getInstance(keyPairEnc);
        assertTrue(reconstructedPrivateKey.equals(generatedPrivateKey));


        reconstructedPrivateKey.getPublicKey();
        generatedPrivateKey.getPublicKey();

        //
        // Are they still equal, public keys are only checked if they both
        // exist because they are only created when requested as they are derived from the private key.
        //
        assertTrue(reconstructedPrivateKey.equals(generatedPrivateKey));

        //
        // Check the reconstructed key can verify a signature.
        //
        assertTrue(HSS.verifySignature(reconstructedPrivateKey.getPublicKey(), sigFromGeneratedPrivateKey, Hex.decode("ABCDEF")));

    }


    /**
     * Test Case 1 Signature
     * From https://tools.ietf.org/html/rfc8554#appendix-F
     *
     * @throws Exception
     */
    public void testHSSVector_1()
        throws Exception
    {
        ArrayList<byte[]> blocks = loadVector("/org/bouncycastle/pqc/crypto/test/lms/testcase_1.txt");

        HSSPublicKeyParameters publicKey = HSSPublicKeyParameters.getInstance(blocks.get(0));
        byte[] message = blocks.get(1);
        HSSSignature signature = HSSSignature.getInstance(blocks.get(2), publicKey.getL());
        assertTrue("Test Case 1 ", HSS.verifySignature(publicKey, signature, message));
    }

    /**
     * Test Case 1 Signature
     * From https://tools.ietf.org/html/rfc8554#appendix-F
     *
     * @throws Exception
     */
    public void testHSSVector_2()
        throws Exception
    {

        ArrayList<byte[]> blocks = loadVector("/org/bouncycastle/pqc/crypto/test/lms/testcase_2.txt");

        HSSPublicKeyParameters publicKey = HSSPublicKeyParameters.getInstance(blocks.get(0));
        byte[] message = blocks.get(1);
        byte[] sig = blocks.get(2);
        HSSSignature signature = HSSSignature.getInstance(sig, publicKey.getL());
        assertTrue("Test Case 2 Signature", HSS.verifySignature(publicKey, signature, message));

        LMSPublicKeyParameters lmsPub = LMSPublicKeyParameters.getInstance(blocks.get(3));
        LMSSignature lmsSignature = LMSSignature.getInstance(blocks.get(4));

        assertTrue("Test Case 2 Signature 2", LMS.verifySignature(lmsPub, lmsSignature, message));

    }


    private ArrayList<byte[]> loadVector(String vector)
        throws Exception
    {
        InputStream inputStream = HSSTests.class.getResourceAsStream(vector);
        BufferedReader bin = new BufferedReader(new InputStreamReader(inputStream));
        String line;
        ArrayList<byte[]> blocks = new ArrayList<byte[]>();
        StringBuffer sw = new StringBuffer();
        while ((line = bin.readLine()) != null)
        {
            if (line.startsWith("!"))
            {
                if (sw.length() > 0)
                {
                    blocks.add(LMSVectorUtils.extract$PrefixedBytes(sw.toString()));
                    sw.setLength(0);
                }
            }
            sw.append(line);
            sw.append("\n");
        }

        if (sw.length() > 0)
        {
            blocks.add(LMSVectorUtils.extract$PrefixedBytes(sw.toString()));
            sw.setLength(0);
        }
        return blocks;
    }


    /**
     * Test the generation of public keys from private key SEED and I.
     * Level 0
     *
     * @throws Exception
     */
    public void testGenPublicKeys_L0()
        throws Exception
    {

        byte[] seed = Hex.decode("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439");
        int level = 0;
        LMSPrivateKeyParameters lmsPrivateKey = LMS.generateKeys(LMSigParameters.getParametersForType(6), LMOtsParameters.getParametersForType(3), level, Hex.decode("d08fabd4a2091ff0a8cb4ed834e74534"), seed);
        LMSPublicKeyParameters publicKey = lmsPrivateKey.getPublicKey();
        assertTrue(Arrays.areEqual(publicKey.getT1(), Hex.decode("32a58885cd9ba0431235466bff9651c6c92124404d45fa53cf161c28f1ad5a8e")));
        assertTrue(Arrays.areEqual(publicKey.getI(), Hex.decode("d08fabd4a2091ff0a8cb4ed834e74534")));
    }

    /**
     * Test the generation of public keys from private key SEED and I.
     * Level 1;
     *
     * @throws Exception
     */
    public void testGenPublicKeys_L1()
        throws Exception
    {

        byte[] seed = Hex.decode("a1c4696e2608035a886100d05cd99945eb3370731884a8235e2fb3d4d71f2547");
        int level = 1;
        LMSPrivateKeyParameters lmsPrivateKey = LMS.generateKeys(LMSigParameters.getParametersForType(5), LMOtsParameters.getParametersForType(4), level, Hex.decode("215f83b7ccb9acbcd08db97b0d04dc2b"), seed);
        LMSPublicKeyParameters publicKey = lmsPrivateKey.getPublicKey();
        assertTrue(Arrays.areEqual(publicKey.getT1(), Hex.decode("a1cd035833e0e90059603f26e07ad2aad152338e7a5e5984bcd5f7bb4eba40b7")));
        assertTrue(Arrays.areEqual(publicKey.getI(), Hex.decode("215f83b7ccb9acbcd08db97b0d04dc2b")));
    }


    public void testGenerate()
        throws Exception
    {

        //
        // Generate an HSS key pair for a two level HSS scheme.
        // then use that to verify it compares with a value from the same reference implementation.
        // Then check components of it serialize and deserialize properly.
        //


        byte[] fixedSource = new byte[8192];
        for (int t = 0; t < fixedSource.length; t++)
        {
            fixedSource[t] = 1;
        }

        SecureRandom rand = new FixedSecureRandom(fixedSource);

        HSSPrivateKeyParameters keyPair = HSS.generateHSSKeyPair(
            HSSKeyGenerationParameters.builder(2)
                .setLmsParameters(
                    new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
                    new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w2))
                .setLmsEntropySource(rand)
                .build()
        );


        //
        // Generated from reference implementation.
        // check the encoded form of the public key matches.
        //
        String expectedPk = "0000000200000005000000030101010101010101010101010101010166BF6F5816EEE4BBF33C50ACB480E09B4169EBB533372959BC4315C388E501AC";
        byte[] pkEnc = keyPair.getPublicKey().getEncoded();
        assertTrue(Arrays.areEqual(Hex.decode(expectedPk), pkEnc));

        //
        // Check that HSS public keys have value equality after deserialization.
        // Use external sourced pk for deserialization.
        //
        assertTrue("HSSPrivateKeyParameterss equal are deserialization", keyPair.getPublicKey().equals(HSSPublicKeyParameters.getInstance(Hex.decode(expectedPk))));


        //
        // Generate, hopefully the same HSSKetPair for the same entropy.
        // This is a sanity test
        //
        {
            SecureRandom rand1 = new FixedSecureRandom(fixedSource);

            HSSPrivateKeyParameters regenKeyPair = HSS.generateHSSKeyPair(
                HSSKeyGenerationParameters.builder(2)
                    .setLmsParameters(
                        new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
                        new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w2))
                    .setLmsEntropySource(rand1)
                    .build()
            );

            assertTrue("Both generated keys are the same", Arrays.areEqual(regenKeyPair.getPublicKey().getEncoded(), keyPair.getPublicKey().getEncoded()));

            assertTrue("same private key size", keyPair.getKeys().size() == regenKeyPair.getKeys().size());

            for (int t = 0; t < keyPair.getKeys().size(); t++)
            {
                //
                // Check the private keys can be encoded and are the same.
                //
                byte[] pk1 = keyPair.getKeys().get(t).getEncoded();
                byte[] pk2 = regenKeyPair.getKeys().get(t).getEncoded();
                assertTrue(Arrays.areEqual(pk1, pk2));

                //
                // Deserialize them and see if they still equal.
                //
                LMSPrivateKeyParameters pk1O = LMSPrivateKeyParameters.getInstance(pk1);
                LMSPrivateKeyParameters pk2O = LMSPrivateKeyParameters.getInstance(pk2);

                assertTrue("LmsPrivateKey still equal after deserialization", pk1O.equals(pk2O));

            }
        }

        //
        // This time we will generate another set of keys using a different entropy source.
        // they should be different!
        // Useful for detecting accidental hard coded things.
        //

        {
            // Use a real secure random this time.
            SecureRandom rand1 = new SecureRandom();

            HSSPrivateKeyParameters differentKey = HSS.generateHSSKeyPair(
                HSSKeyGenerationParameters.builder(2)
                    .setLmsParameters(
                        new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
                        new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w2))
                    .setLmsEntropySource(rand1)
                    .build()
            );


            assertFalse("Both generated keys are not the same", Arrays.areEqual(differentKey.getPublicKey().getEncoded(), keyPair.getPublicKey().getEncoded()));


            for (int t = 0; t < keyPair.getKeys().size(); t++)
            {
                //
                // Check the private keys can be encoded and are not the same.
                //
                byte[] pk1 = keyPair.getKeys().get(t).getEncoded();
                byte[] pk2 = differentKey.getKeys().get(t).getEncoded();
                assertFalse("keys not the same", Arrays.areEqual(pk1, pk2));

                //
                // Deserialize them and see if they still equal.
                //
                LMSPrivateKeyParameters pk1O = LMSPrivateKeyParameters.getInstance(pk1);
                LMSPrivateKeyParameters pk2O = LMSPrivateKeyParameters.getInstance(pk2);

                assertFalse("LmsPrivateKey not suddenly equal after deserialization", pk1O.equals(pk2O));

            }

        }

    }


    /**
     * This test takes in a series of vectors generated by adding print statements to code called by
     * the "test_sign.c" test in the reference implementation.
     * <p>
     * The purpose of this test is to ensure that the signatures and public keys exactly match for the
     * same entropy source the values generated by the reference implementation.
     * <p>
     * It also verifies value equality between signature and public key objects as well as
     * complimentary serialization and deserialization.
     *
     * @throws Exception
     */
    public void testVectorsFromReference()
        throws Exception
    {

        String[] lines = new String(Streams.readAll(HSSTests.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/lms/depth_1.txt"))).split("\n");

        int d = 0;
        List<LMSigParameters> lmsParameters = new ArrayList<LMSigParameters>();
        List<LMOtsParameters> lmOtsParameters = new ArrayList<LMOtsParameters>();
        byte[] message = null;
        byte[] hssPubEnc = null;
        byte[] encodedSigFromVector = null;
        ByteArrayOutputStream fixedESBuffer = new ByteArrayOutputStream();

        int j = 0;

        for (String line : lines)
        {
            line = line.trim();
            if (line.startsWith("#") || line.length() == 0)
            {
                continue;
            }

            if (line.startsWith("Depth:"))
            {
                d = Integer.parseInt(line.substring("Depth:".length()).trim());
            }
            else if (line.startsWith("LMType:"))
            {
                int typ = Integer.parseInt(line.substring("LMType:".length()).trim());
                lmsParameters.add(LMSigParameters.getParametersForType(typ));
            }
            else if (line.startsWith("LMOtsType:"))
            {
                int typ = Integer.parseInt(line.substring("LMOtsType:".length()).trim());
                lmOtsParameters.add(LMOtsParameters.getParametersForType(typ));
            }
            else if (line.startsWith("Rand:"))
            {
                fixedESBuffer.write(Hex.decode(line.substring("Rand:".length()).trim()));
            }
            else if (line.startsWith("HSSPublicKey:"))
            {
                hssPubEnc = Hex.decode(line.substring("HSSPublicKey:".length()).trim());
            }
            else if (line.startsWith("Message:"))
            {
                message = Hex.decode(line.substring("Message:".length()).trim());
            }
            else if (line.startsWith("Signature:"))
            {
                j++;

                encodedSigFromVector = Hex.decode(line.substring("Signature:".length()).trim());

                //
                // Assumes Signature is the last element in the set of vectors.
                //
                FixedSecureRandom fixRnd = new FixedSecureRandom(fixedESBuffer.toByteArray());
                fixedESBuffer.reset();

                //
                // Deserialize pub key from reference impl.
                //
                HSSPublicKeyParameters vectorSourcedPubKey = HSSPublicKeyParameters.getInstance(hssPubEnc);
                List<LMSParameters> lmsParams = new ArrayList<LMSParameters>();

                for (int i = 0; i != lmsParameters.size(); i++)
                {
                    lmsParams.add(new LMSParameters(lmsParameters.get(i), lmOtsParameters.get(i)));
                }

                //
                // Using our fixed entropy source generate hss keypair
                //
                HSSPrivateKeyParameters keyPair = HSS.generateHSSKeyPair(
                    HSSKeyGenerationParameters.builder(d)
                        .setLmsParameters(lmsParams)
                        .setLmsEntropySource(fixRnd)
                        .build()
                );

                { // Public Key should match vector.

                    // Encoded value equality.
                    HSSPublicKeyParameters generatedPubKey = keyPair.getPublicKey();
                    assertTrue(Arrays.areEqual(hssPubEnc, generatedPubKey.getEncoded()));

                    // Value equality.
                    assertTrue(vectorSourcedPubKey.equals(generatedPubKey));
                }


                //
                // Generate a signature using the keypair we generated.
                //
                HSSSignature sig = HSS.generateSignature(keyPair, message, fixRnd);


                if (!Arrays.areEqual(sig.getEncoded(), encodedSigFromVector))
                {
                    HSSSignature signatureFromVector = HSSSignature.getInstance(encodedSigFromVector, d);
                    signatureFromVector.equals(sig);
                    System.out.println();

                }

                // check encoding signature matches.
                assertTrue(Arrays.areEqual(sig.getEncoded(), encodedSigFromVector));

                // Check we can verify our generated signature with the vectors sourced public key.
                assertTrue(HSS.verifySignature(vectorSourcedPubKey, sig, message));

                // Deserialize the signature from the vector.
                HSSSignature signatureFromVector = HSSSignature.getInstance(encodedSigFromVector, d);

                // Can we verify signature from vector with public key from vector.
                assertTrue(HSS.verifySignature(vectorSourcedPubKey, signatureFromVector, message));

                //
                // Check our generated signature and the one deserialized from the vector
                // have value equality.
                assertTrue(signatureFromVector.equals(sig));


                //
                // Other tests vandalise HSS signatures to check they fail when tampered with
                // we won't do that again here.
                //


                d = 0;
                lmOtsParameters.clear();
                lmsParameters.clear();
                message = null;
                hssPubEnc = null;
                encodedSigFromVector = null;

            }


        }

    }


    /**
     * Take an HSS key pair and exhaust its signing capacity.
     *
     * @throws Exception
     */
    public void testSignUnitExhaustion()
        throws Exception
    {

        SecureRandom rand = new SecureRandom()
        {
            @Override
            public void nextBytes(byte[] bytes)
            {
                for (int t = 0; t < bytes.length; t++)
                {
                    bytes[t] = 1;
                }
            }
        };

        HSSPrivateKeyParameters keyPair = HSS.generateHSSKeyPair(
            HSSKeyGenerationParameters.builder(2)
                .setLmsParameters(
                    new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w2),
                    new LMSParameters(LMSigParameters.lms_sha256_n32_h10, LMOtsParameters.sha256_n32_w8))
                .setLmsEntropySource(rand)
                .build()
        );

        HSSPublicKeyParameters pk = keyPair.getPublicKey();


        int msgCtr = 0;
        byte[] message = new byte[32];

        //
        // There should be a max of 512 signatures for this key.
        //

        assertTrue(keyPair.getUsagesRemaining() == 32768);

        try
        {
            while (msgCtr < 8193) // Just a number..
            {
                Pack.intToBigEndian(msgCtr, message, 0);
                HSSSignature sig = HSS.generateSignature(keyPair, message, rand);
                assertTrue(HSS.verifySignature(pk, sig, message));



                assertTrue(sig.getSignature().getParameter().getType() == LMSigParameters.lms_sha256_n32_h10.getType());

                {
                    //
                    // Vandalise hss signature.
                    //
                    byte[] rawSig = sig.getEncoded();
                    rawSig[100] ^= 1;
                    HSSSignature parsedSig = HSSSignature.getInstance(rawSig, pk.getL());
                    assertFalse(HSS.verifySignature(pk, parsedSig, message));

                    try
                    {
                        HSSSignature.getInstance(rawSig, 0);
                        fail();
                    }
                    catch (IllegalStateException ex)
                    {
                        assertTrue(ex.getMessage().contains("nspk exceeded maxNspk"));
                    }

                }


                {
                    //
                    // Vandalise hss message
                    //
                    byte[] newMsg = message.clone();
                    newMsg[1] ^= 1;
                    assertFalse(HSS.verifySignature(pk, sig, newMsg));
                }


                {
                    //
                    // Vandalise public key
                    //
                    byte[] pkEnc = pk.getEncoded();
                    pkEnc[35] ^= 1;
                    HSSPublicKeyParameters rebuiltPk = HSSPublicKeyParameters.getInstance(pkEnc);
                    assertFalse(HSS.verifySignature(rebuiltPk, sig, message));
                }
                msgCtr++;


                LMSPrivateKeyParameters lmsKey =  keyPair.getNextSigningKey(rand);

                lmsKey.getNextOtsPrivateKey();
                lmsKey.getNextOtsPrivateKey();
                lmsKey.getNextOtsPrivateKey();

            }
            fail();
        }
        catch (ExhaustedPrivateKeyException ex)
        {
            assertTrue(keyPair.getUsagesRemaining() == 0);
            assertTrue(msgCtr == 8192);
            assertTrue(ex.getMessage().contains("hss private key is exhausted"));
        }

    }


}

