package org.bouncycastle.crypto.params;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;
import org.bouncycastle.crypto.prng.FixedSecureRandom;
import org.bouncycastle.crypto.ExhaustedPrivateKeyException;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.crypto.generators.HSSKeyPairGenerator;
import org.bouncycastle.crypto.signers.HSSSigner;
import org.bouncycastle.crypto.signers.LMSSigner;
import org.bouncycastle.crypto.signers.lms.LMSEngine;
import org.bouncycastle.crypto.signers.lms.LMSSignature;

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


        HSSPrivateKeyParameters generatedPrivateKey = LMSEngine.generateHSSKeyPair(
            new HSSKeyGenerationParameters(new LMSParameters[]{
                new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
                new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w2),
            }, rand)
        );

        byte[] sigFromGeneratedPrivateKey = sign(generatedPrivateKey, Hex.decode("ABCDEF"));

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
        assertTrue(verify(reconstructedPrivateKey.getPublicKey(), sigFromGeneratedPrivateKey, Hex.decode("ABCDEF")));

    }

    /**
     * A multi-level HSS private key in the version 0 encoding - written by any release before
     * the tree-cache feature, whose component keys end at the master secret - must still decode
     * and sign. The component keys share one stream, so the cache cannot be detected from "more
     * bytes available": before the encoding version told the parser whether the cache field is
     * present, 4 bytes of the next component key were consumed as a phantom cache count and a
     * d &gt; 1 key from an older release failed to decode (github #2365).
     */
    public void testVersion0HssKeyDecodes()
        throws Exception
    {
        implVersion0HssKeyDecodes(1);
        implVersion0HssKeyDecodes(2);
        implVersion0HssKeyDecodes(3);
    }

    private void implVersion0HssKeyDecodes(int d)
        throws Exception
    {
        HSSPrivateKeyParameters generated = generateKey(d);

        LMSVectorUtils.Encoder composer = LMSVectorUtils.compose()
            .u32str(0) // version 0: pre-tree-cache component keys
            .u32str(generated.getL())
            .u64str(generated.getIndex())
            .u64str(generated.getIndexLimit())
            .bool(false);

        for (LMSPrivateKeyParameters key : generated.getKeys())
        {
            composer.bytes(version0KeyEncoding(key));
        }
        for (LMSSignature s : generated.getSig())
        {
            composer.bytes(s.getEncoded());
        }

        HSSPrivateKeyParameters decoded = HSSPrivateKeyParameters.getInstance(composer.build());

        assertEquals(generated.getL(), decoded.getL());
        assertEquals(generated.getIndex(), decoded.getIndex());
        assertEquals(generated.getIndexLimit(), decoded.getIndexLimit());
        for (int t = 0; t < d; t++)
        {
            assertFalse("version 0 component key carries no cache", decoded.getKeys().get(t).isTreeCachePrimed());
        }

        byte[] signature = sign(decoded, Hex.decode("ABCDEF"));
        assertTrue(verify(generated.getPublicKey(), signature, Hex.decode("ABCDEF")));
    }

    /**
     * The current encoding is version 1: the component keys always carry the tree-cache field,
     * and the version - the first four bytes - is what a pre-cache release's decoder rejects
     * cleanly instead of misparsing the cache as key material.
     */
    public void testVersion1HssKeyRoundTrip()
        throws Exception
    {
        HSSPrivateKeyParameters generated = generateKey(2);

        byte[] enc = generated.getEncoded();

        assertEquals("encoding version", 1, Pack.bigEndianToInt(enc, 0));

        HSSPrivateKeyParameters decoded = HSSPrivateKeyParameters.getInstance(enc);

        assertTrue(decoded.equals(generated));
        for (int t = 0; t < 2; t++)
        {
            assertTrue("version 1 component key carries the cache", decoded.getKeys().get(t).isTreeCachePrimed());
        }

        byte[] signature = sign(decoded, Hex.decode("ABCDEF"));
        assertTrue(verify(generated.getPublicKey(), signature, Hex.decode("ABCDEF")));
    }

    private static HSSPrivateKeyParameters generateKey(int d)
    {
        LMSParameters[] lmsParameters = new LMSParameters[d];
        for (int t = 0; t < d; t++)
        {
            lmsParameters[t] = new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4);
        }

        return LMSEngine.generateHSSKeyPair(new HSSKeyGenerationParameters(lmsParameters, new SecureRandom()));
    }

    // Exactly what LMSPrivateKeyParameters.getEncoded() produced before the tree-cache feature:
    // version, type, otstype, I, q, maxQ, secret length, secret - no trailing cache.
    private static byte[] version0KeyEncoding(LMSPrivateKeyParameters key)
        throws Exception
    {
        return LMSVectorUtils.compose()
            .u32str(0)
            .u32str(key.getSigParameters().getType())
            .u32str(key.getOtsParameters().getType())
            .bytes(key.getI())
            .u32str((int)key.getIndex())
            .u32str((int)key.getIndexLimit())
            .u32str(key.getMasterSecret().length)
            .bytes(key.getMasterSecret())
            .build();
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
        List<byte[]> blocks = loadVector("testcase_1.txt");

        HSSPublicKeyParameters publicKey = HSSPublicKeyParameters.getInstance(blocks.get(0));
        byte[] message = blocks.get(1);
        byte[] signature = blocks.get(2);
        assertTrue("Test Case 1 ", verify(publicKey, signature, message));
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

        List<byte[]> blocks = loadVector("testcase_2.txt");

        HSSPublicKeyParameters publicKey = HSSPublicKeyParameters.getInstance(blocks.get(0));
        byte[] message = blocks.get(1);
        byte[] sig = blocks.get(2);
        byte[] signature = sig;
        assertTrue("Test Case 2 Signature", verify(publicKey, signature, message));

        LMSPublicKeyParameters lmsPub = LMSPublicKeyParameters.getInstance(blocks.get(3));
        assertTrue("Test Case 2 Signature 2", verifyLms(lmsPub, blocks.get(4), message));

    }


    private List<byte[]> loadVector(String vector)
        throws Exception
    {
        InputStream inputStream = TestResourceFinder.findTestResource("pqc/crypto/lms", vector);
        BufferedReader bin = new BufferedReader(new InputStreamReader(inputStream));
        String line;
        List<byte[]> blocks = new ArrayList<byte[]>();
        StringBuilder sw = new StringBuilder();
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
        LMSPrivateKeyParameters lmsPrivateKey = lmsKey(LMSigParameters.getParametersForType(6), LMOtsParameters.getParametersForType(3), level, Hex.decode("d08fabd4a2091ff0a8cb4ed834e74534"), seed);
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
        LMSPrivateKeyParameters lmsPrivateKey = lmsKey(LMSigParameters.getParametersForType(5), LMOtsParameters.getParametersForType(4), level, Hex.decode("215f83b7ccb9acbcd08db97b0d04dc2b"), seed);
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

        HSSPrivateKeyParameters keyPair = LMSEngine.generateHSSKeyPair(
            new HSSKeyGenerationParameters(new LMSParameters[]{
                new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
                new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w2),
            }, rand));


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

            HSSPrivateKeyParameters regenKeyPair = LMSEngine.generateHSSKeyPair(
                new HSSKeyGenerationParameters(new LMSParameters[]{
                    new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
                    new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w2),
                }, rand1));


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

            HSSPrivateKeyParameters differentKey = LMSEngine.generateHSSKeyPair(
                new HSSKeyGenerationParameters(new LMSParameters[]{
                    new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
                    new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w2),
                }, rand1)
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

        String[] lines = new String(Streams.readAll(TestResourceFinder.findTestResource("pqc/crypto/lms", "depth_1.txt"))).split("\n");

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


                HSSPrivateKeyParameters keyPair = LMSEngine.generateHSSKeyPair(
                    new HSSKeyGenerationParameters(
                        lmsParams.toArray(new LMSParameters[lmsParams.size()]), fixRnd)
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
                byte[] sig = sign(keyPair, message);


                if (!Arrays.areEqual(sig, encodedSigFromVector))
                {
                    byte[] signatureFromVector = encodedSigFromVector;
                    Arrays.areEqual(signatureFromVector, sig);
                    // System.out.println();

                }

                // check encoding signature matches.
                assertTrue(Arrays.areEqual(sig, encodedSigFromVector));

                // Check we can verify our generated signature with the vectors sourced public key.
                assertTrue(verify(vectorSourcedPubKey, sig, message));

                // Deserialize the signature from the vector.
                byte[] signatureFromVector = encodedSigFromVector;

                // Can we verify signature from vector with public key from vector.
                assertTrue(verify(vectorSourcedPubKey, signatureFromVector, message));

                //
                // Check our generated signature and the one deserialized from the vector
                // have value equality.
                assertTrue(Arrays.areEqual(signatureFromVector, sig));


                //
                // Other tests vandalise HSS signatures to check they fail when tampered with
                // we won't do that again here.
                //


                d = 0;
                lmOtsParameters.clear();
                lmsParameters.clear();
                message = null;
                hssPubEnc = null;


            }


        }

    }

    public void testVectorsFromReference_Expanded()
        throws Exception
    {

        String[] lines = new String(Streams.readAll(TestResourceFinder.findTestResource("pqc/crypto/lms", "expansion.txt"))).split("\n");

        int d = 0;
        List<LMSigParameters> lmsParameters = new ArrayList<LMSigParameters>();
        List<LMOtsParameters> lmOtsParameters = new ArrayList<LMOtsParameters>();
        byte[] message = null;
        byte[] hssPubEnc = null;
        byte[] encodedSigFromVector = null;
        ByteArrayOutputStream fixedESBuffer = new ByteArrayOutputStream();
        List<byte[]> sigVectors = new ArrayList<byte[]>();


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
                sigVectors.add(Hex.decode(line.substring("Signature:".length()).trim()));
            }
        }

        //
        // Assumes Signature is the last element in the set of vectors.
        //
        FixedSecureRandom fixRnd = new FixedSecureRandom(fixedESBuffer.toByteArray());
        fixedESBuffer.reset();

        List<LMSParameters> lmsParams = new ArrayList<LMSParameters>();

        for (int i = 0; i != lmsParameters.size(); i++)
        {
            lmsParams.add(new LMSParameters(lmsParameters.get(i), lmOtsParameters.get(i)));
        }

        HSSPrivateKeyParameters keyPair = LMSEngine.generateHSSKeyPair(
            new HSSKeyGenerationParameters(
                lmsParams.toArray(new LMSParameters[lmsParams.size()]), fixRnd)
        );

        assertTrue(Arrays.areEqual(hssPubEnc, keyPair.getPublicKey().getEncoded()));

        HSSPublicKeyParameters pubKeyFromVector = HSSPublicKeyParameters.getInstance(hssPubEnc);
        HSSPublicKeyParameters pubKeyGenerated = null;


        assertEquals(1024, keyPair.getUsagesRemaining());
        assertEquals(1024, keyPair.getIndexLimit());
        assertEquals(0, keyPair.getIndex());

        //
        // Split the space up with a shard.
        //

        HSSPrivateKeyParameters shard1 = keyPair.extractKeyShard(500);
        pubKeyGenerated = shard1.getPublicKey();


        HSSPrivateKeyParameters pair = shard1;

        int c = 0;
        for (int i = 0; i < keyPair.getIndexLimit(); i++)
        {
            if (i == 500)
            {
                try
                {
                    pair.incrementIndex();
                    fail("shard should be exhausted.");
                }
                catch (ExhaustedPrivateKeyException ex)
                {
                    assertEquals("hss private key shard is exhausted", ex.getMessage());
                }
                pair = keyPair;
                pubKeyGenerated = keyPair.getPublicKey();

                assertEquals(pubKeyGenerated, shard1.getPublicKey());

            }

            if (i % 5 == 0)
            {
                byte[] sigCalculated = sign(pair, message);
                assertTrue(Arrays.areEqual(sigCalculated, sigVectors.get(c)));

                assertTrue(verify(pubKeyFromVector, sigCalculated, message));
                assertTrue(verify(pubKeyGenerated, sigCalculated, message));

                byte[] sigFromVector = sigVectors.get(c);

                assertTrue(verify(pubKeyFromVector, sigFromVector, message));
                assertTrue(verify(pubKeyGenerated, sigFromVector, message));


                assertTrue(Arrays.areEqual(sigCalculated, sigFromVector));


                c++;
            }
            else
            {
                pair.incrementIndex();
            }
        }
    }


    /**
     * Test remaining calculation is accurate and a new key is generated when
     * all the ots keys for that level are consumed.
     *
     * @throws Exception
     */
    public void testRemaining()
        throws Exception
    {
        HSSPrivateKeyParameters keyPair = LMSEngine.generateHSSKeyPair(
            new HSSKeyGenerationParameters(new LMSParameters[]{
                new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w2),
                new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w2)
            }, new SecureRandom())
        );


        LMSPrivateKeyParameters lmsKey = keyPair.getKeys().get(keyPair.getL() - 1);
        //
        // There should be a max of 32768 signatures for this key.
        //
        assertEquals(1024, keyPair.getUsagesRemaining());

        keyPair.incrementIndex();
        keyPair.incrementIndex();
        keyPair.incrementIndex();
        keyPair.incrementIndex();
        keyPair.incrementIndex();

        assertEquals(5, keyPair.getIndex()); // Next key is at index 5!


        assertEquals(1024 - 5, keyPair.getUsagesRemaining());


        HSSPrivateKeyParameters shard = keyPair.extractKeyShard(10);

        assertEquals(10, shard.getUsagesRemaining());
        assertEquals(15, shard.getIndexLimit());
        assertEquals(5, shard.getIndex());

        // Should not be the same.
        assertFalse(shard.getIndex() == keyPair.getIndex());

        //
        // Should be 17 left, it will throw if it has been exhausted.
        //
        for (int t = 0; t < 17; t++)
        {
            keyPair.incrementIndex();
        }

        // We have used 32 keys.
        assertEquals(1024 - 32, keyPair.getUsagesRemaining());


        sign(keyPair, "Foo".getBytes());

        //
        // This should trigger the generation of a new key.
        //
        LMSPrivateKeyParameters potentialNewLMSKey = keyPair.getKeys().get(keyPair.getL() - 1);
        assertFalse(potentialNewLMSKey.equals(lmsKey));
    }

    public void testSharding()
        throws Exception
    {
        HSSPrivateKeyParameters keyPair = LMSEngine.generateHSSKeyPair(
            new HSSKeyGenerationParameters(new LMSParameters[]{
                new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w2),
                new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w2)
            }, new SecureRandom())
        );

        assertEquals(1024, keyPair.getUsagesRemaining());
        assertEquals(1024, keyPair.getIndexLimit());
        assertEquals(0, keyPair.getIndex());
        assertFalse(keyPair.isShard());
        keyPair.incrementIndex();


        //
        // Take a shard that should cross boundaries
        //
        HSSPrivateKeyParameters shard = keyPair.extractKeyShard(48);
        assertTrue(shard.isShard());
        assertEquals(48, shard.getUsagesRemaining());
        assertEquals(49, shard.getIndexLimit());
        assertEquals(1, shard.getIndex());

        assertEquals(49, keyPair.getIndex());


        int t = 47;
        while (--t >= 0)
        {
            shard.incrementIndex();
        }

        byte[] sig = sign(shard, "Cats".getBytes());

        //
        // Test it validates and nothing has gone wrong with the public keys.
        //
        assertTrue(verify(keyPair.getPublicKey(), sig, "Cats".getBytes()));
        assertTrue(verify(shard.getPublicKey(), sig, "Cats".getBytes()));

        // Signing again should fail.

        try
        {
            sign(shard, "Cats".getBytes());
            fail();
        }
        catch (Exception ex)
        {
            assertEquals("hss private key shard is exhausted", ex.getMessage());
        }

        // Should work without throwing.
        sign(keyPair, "Cats".getBytes());


        // System.out.println();

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

        HSSPrivateKeyParameters keyPair = LMSEngine.generateHSSKeyPair(
            new HSSKeyGenerationParameters(new LMSParameters[]{
                new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w2),
                new LMSParameters(LMSigParameters.lms_sha256_n32_h10, LMOtsParameters.sha256_n32_w1),
            }, rand)
        );

        HSSPublicKeyParameters pk = keyPair.getPublicKey();


        int ctr = 0;
        byte[] message = new byte[32];

        //
        // There should be a max of 32768 signatures for this key.
        //

        assertTrue(keyPair.getUsagesRemaining() == 32768);

        int mod = 256;
        try
        {
            while (ctr < 32769) // Just a number..
            {

                if (ctr % mod == 0)
                {
                    //
                    // We don't want to check every key.
                    // The test will take over an hour to complete.
                    //

                    Pack.intToBigEndian(ctr, message, 0);
                    byte[] sig = sign(keyPair, message);

                    assertEquals(ctr % 1024, leafSignatureQ(keyPair, sig));

                    // Check there was a post increment in the tail end LMS key.
                    assertEquals("" + ctr, (ctr % 1024) + 1, keyPair.getKeys().get(keyPair.getL() - 1).getIndex());

                    assertEquals(ctr + 1, keyPair.getIndex());


                    // Validate the heirarchial path building was correct.

                    long[] qValues = new long[keyPair.getKeys().size()];
                    long q = ctr;

                    for (int t = keyPair.getKeys().size() - 1; t >= 0; t--)
                    {
                        LMSigParameters sigParameters = keyPair.getKeys().get(t).getSigParameters();
                        int mask = (1 << sigParameters.getH()) - 1;
                        qValues[t] = q & mask;
                        q >>>= sigParameters.getH();
                    }

                    for (int t = 0; t < keyPair.getKeys().size(); t++)
                    {
                        assertEquals("" + ctr, keyPair.getKeys().get(t).getIndex() - 1, qValues[t]);
                    }


                    assertTrue(verify(pk, sig, message));
                    assertEquals(LMSigParameters.lms_sha256_n32_h10.getType(), leafSignatureType(keyPair, sig));

                    {
                        //
                        // Vandalise hss signature.
                        //
                        byte[] rawSig = sig;
                        rawSig[100] ^= 1;
                        byte[] parsedSig = rawSig;
                        assertFalse(verify(pk, parsedSig, message));

                        try
                        {
                            // a key claiming one more level than the signature carries
                            new HSSPublicKeyParameters(pk.getL() + 1, pk.getLMSPublicKey()).generateLMSContext(rawSig);
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
                        assertFalse(verify(pk, sig, newMsg));
                    }


                    {
                        //
                        // Vandalise public key
                        //
                        byte[] pkEnc = pk.getEncoded();
                        pkEnc[35] ^= 1;
                        HSSPublicKeyParameters rebuiltPk = HSSPublicKeyParameters.getInstance(pkEnc);
                        assertFalse(verify(rebuiltPk, sig, message));
                    }
                }
                else
                {
                    // Skip some keys.
                    keyPair.incrementIndex();
                }

                ctr++;

            }
            //// System.out.println(ctr);
            fail();
        }
        catch (ExhaustedPrivateKeyException ex)
        {
            assertTrue(keyPair.getUsagesRemaining() == 0);
            assertTrue(ctr == 32768);
            assertTrue(ex.getMessage().contains("hss private key is exhausted"));
        }

    }



    /**
     * The level count d and the index pair are range checked at decode. Before github #2414 only the
     * version was guarded, so d = 0 decoded and the empty key list then threw an unchecked
     * IndexOutOfBoundsException out of the signing call rather than being refused as a bad key.
     */
    public void testPrivateKeyLevelCountRangeChecked()
        throws Exception
    {
        HSSPrivateKeyParameters key = genHssKey();
        byte[] enc = key.getEncoded();

        // d sits at offset 4, after the version
        int[] badD = { 0, -1, 9, Integer.MIN_VALUE, Integer.MAX_VALUE };
        for (int i = 0; i != badD.length; i++)
        {
            byte[] corrupt = Arrays.clone(enc);
            Pack.intToBigEndian(badD[i], corrupt, 4);
            try
            {
                HSSPrivateKeyParameters.getInstance(corrupt);
                fail("no exception on d = " + badD[i]);
            }
            catch (java.io.IOException e)
            {
                assertTrue(e.getMessage().startsWith("d value of HSS private key out of range"));
            }
        }

        // index at offset 8, maxIndex at 16, both u64
        long[][] badIndex = { { -1L, 1024L }, { 0L, -1L }, { 100L, 10L } };
        for (int i = 0; i != badIndex.length; i++)
        {
            byte[] corrupt = Arrays.clone(enc);
            Pack.longToBigEndian(badIndex[i][0], corrupt, 8);
            Pack.longToBigEndian(badIndex[i][1], corrupt, 16);
            try
            {
                HSSPrivateKeyParameters.getInstance(corrupt);
                fail("no exception on index = " + badIndex[i][0] + " maxIndex = " + badIndex[i][1]);
            }
            catch (java.io.IOException e)
            {
                assertTrue(e.getMessage().startsWith("HSS private key index out of range"));
            }
        }

        // the genuine encoding still decodes and signs verifiably
        HSSPrivateKeyParameters decoded = HSSPrivateKeyParameters.getInstance(enc);
        byte[] msg = Hex.decode("48656c6c6f");
        assertTrue(verify(key.getPublicKey(), sign(decoded, msg), msg));
    }

    /**
     * getInstance(privEnc, pubEnc) cross-checks the root against the public key it is handed, which
     * catches a tree cache that is self-consistent but belongs to a different key. Before github
     * #2414 the parsed public key was assigned to a field that was never read.
     */
    public void testPrivateKeyCheckedAgainstSuppliedPublicKey()
        throws Exception
    {
        HSSPrivateKeyParameters keyA = genHssKey();
        HSSPrivateKeyParameters keyB = genHssKey();

        byte[] privA = keyA.getEncoded();
        byte[] pubA = keyA.getPublicKey().getEncoded();
        byte[] pubB = keyB.getPublicKey().getEncoded();

        // matching pair: accepted, and the parsed public key is the one returned
        HSSPrivateKeyParameters decoded = HSSPrivateKeyParameters.getInstance(privA, pubA);
        assertTrue(Arrays.areEqual(pubA, decoded.getPublicKey().getEncoded()));

        // another key's public key: refused
        try
        {
            HSSPrivateKeyParameters.getInstance(privA, pubB);
            fail("no exception on a public key from a different private key");
        }
        catch (java.io.IOException e)
        {
            assertTrue(e.getMessage().startsWith("HSS private key tree cache does not match"));
        }
    }

    private static HSSPrivateKeyParameters genHssKey()
    {
        HSSKeyPairGenerator gen = new HSSKeyPairGenerator();
        gen.init(new HSSKeyGenerationParameters(new LMSParameters[]{
            new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1),
            new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1) },
            new SecureRandom()));
        return (HSSPrivateKeyParameters)gen.generateKeyPair().getPrivate();
    }

    private static byte[] sign(HSSPrivateKeyParameters key, byte[] message)
    {
        HSSSigner signer = new HSSSigner();
        signer.init(true, key);
        return signer.generateSignature(message);
    }

    private static boolean verify(HSSPublicKeyParameters key, byte[] signature, byte[] message)
    {
        HSSSigner signer = new HSSSigner();
        signer.init(false, key);
        return signer.verifySignature(message, signature);
    }

    private static boolean verifyLms(LMSPublicKeyParameters key, byte[] signature, byte[] message)
    {
        LMSSigner signer = new LMSSigner();
        signer.init(false, key);
        return signer.verifySignature(message, signature);
    }

    // RFC 8554 sec. 5.2, Algorithm 5: an LMS private key positioned at index q.
    private static LMSPrivateKeyParameters lmsKey(LMSigParameters sigParams, LMOtsParameters otsParams, int q, byte[] I, byte[] seed)
    {
        return new LMSPrivateKeyParameters(sigParams, otsParams, q, I, 1 << sigParams.getH(), seed);
    }

    // The leaf tree's LMS signature is the tail of an HSS signature (RFC 8554 sec. 6.1); its
    // length follows from the leaf key's parameters (sec. 5.4): u32str(q) || ots_signature ||
    // u32str(type) || path, where ots_signature is u32str(otstype) || C || y (sec. 4.5).
    private static int leafSignatureOffset(HSSPrivateKeyParameters key, byte[] hssSignature)
    {
        LMSPrivateKeyParameters leaf = key.getKeys().get(key.getL() - 1);
        int n = leaf.getOtsParameters().getN();
        int p = leaf.getOtsParameters().getP();
        int h = leaf.getSigParameters().getH();
        int m = leaf.getSigParameters().getM();

        return hssSignature.length - (4 + (4 + n + p * n) + 4 + h * m);
    }

    private static int leafSignatureQ(HSSPrivateKeyParameters key, byte[] hssSignature)
    {
        return Pack.bigEndianToInt(hssSignature, leafSignatureOffset(key, hssSignature));
    }

    private static int leafSignatureType(HSSPrivateKeyParameters key, byte[] hssSignature)
    {
        LMSPrivateKeyParameters leaf = key.getKeys().get(key.getL() - 1);
        int h = leaf.getSigParameters().getH();
        int m = leaf.getSigParameters().getM();

        return Pack.bigEndianToInt(hssSignature, hssSignature.length - h * m - 4);
    }
}
