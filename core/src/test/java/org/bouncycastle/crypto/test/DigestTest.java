package org.bouncycastle.crypto.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Random;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.EncodableDigest;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.TestFailedException;

public abstract class DigestTest
    extends SimpleTest
{
    private Digest digest;
    private String[] input;
    private String[] results;

    DigestTest(
        Digest digest,
        String[] input,
        String[] results)
    {
        this.digest = digest;
        this.input = input;
        this.results = results;
    }

    public String getName()
    {
        return digest.getAlgorithmName();
    }

    public void performTest()
    {
        byte[] resBuf = new byte[digest.getDigestSize()];

        for (int i = 0; i < input.length - 1; i++)
        {
            byte[] m = toByteArray(input[i]);

            vectorTest(digest, i, resBuf, m, Hex.decode(results[i]));
        }

        offsetTest(digest, 0, toByteArray(input[0]), Hex.decode(results[0]));

        byte[] lastV = toByteArray(input[input.length - 1]);
        byte[] lastDigest = Hex.decode(results[input.length - 1]);

        vectorTest(digest, input.length - 1, resBuf, lastV, Hex.decode(results[input.length - 1]));

        testClone(resBuf, lastV, lastDigest);
        testMemo(resBuf, lastV, lastDigest);
        if (digest instanceof EncodableDigest)
        {
            testEncodedState(resBuf, lastV, lastDigest);
        }
    }

    private void testEncodedState(byte[] resBuf, byte[] input, byte[] expected)
    {
        // test state encoding;
        digest.update(input, 0, input.length / 2);

        // copy the Digest
        Digest copy1 = cloneDigest(((EncodableDigest)digest).getEncodedState());
        Digest copy2 = cloneDigest(((EncodableDigest)copy1).getEncodedState());

        digest.update(input, input.length / 2, input.length - input.length / 2);

        digest.doFinal(resBuf, 0);

        if (!areEqual(expected, resBuf))
        {
            fail("failing state vector test", expected, new String(Hex.encode(resBuf)));
        }

        copy1.update(input, input.length / 2, input.length - input.length / 2);
        copy1.doFinal(resBuf, 0);

        if (!areEqual(expected, resBuf))
        {
            fail("failing state copy1 vector test", expected, new String(Hex.encode(resBuf)));
        }

        copy2.update(input, input.length / 2, input.length - input.length / 2);
        copy2.doFinal(resBuf, 0);

        if (!areEqual(expected, resBuf))
        {
            fail("failing state copy2 vector test", expected, new String(Hex.encode(resBuf)));
        }
    }

    private void testMemo(byte[] resBuf, byte[] input, byte[] expected)
    {
        Memoable m = (Memoable)digest;

        digest.update(input, 0, input.length / 2);

        // copy the Digest
        Memoable copy1 = m.copy();
        Memoable copy2 = copy1.copy();

        digest.update(input, input.length / 2, input.length - input.length / 2);
        digest.doFinal(resBuf, 0);

        if (!areEqual(expected, resBuf))
        {
            fail("failing memo vector test", results[results.length - 1], new String(Hex.encode(resBuf)));
        }

        m.reset(copy1);

        digest.update(input, input.length / 2, input.length - input.length / 2);
        digest.doFinal(resBuf, 0);

        if (!areEqual(expected, resBuf))
        {
            fail("failing memo reset vector test", results[results.length - 1], new String(Hex.encode(resBuf)));
        }

        Digest md = (Digest)copy2;

        md.update(input, input.length / 2, input.length - input.length / 2);
        md.doFinal(resBuf, 0);

        if (!areEqual(expected, resBuf))
        {
            fail("failing memo copy vector test", results[results.length - 1], new String(Hex.encode(resBuf)));
        }
    }

    private void testClone(byte[] resBuf, byte[] input, byte[] expected)
    {
        digest.update(input, 0, input.length / 2);

        // clone the Digest
        Digest d = cloneDigest(digest);

        digest.update(input, input.length / 2, input.length - input.length / 2);
        digest.doFinal(resBuf, 0);

        if (!areEqual(expected, resBuf))
        {
            fail("failing clone vector test", results[results.length - 1], new String(Hex.encode(resBuf)));
        }

        d.update(input, input.length / 2, input.length - input.length / 2);
        d.doFinal(resBuf, 0);

        if (!areEqual(expected, resBuf))
        {
            fail("failing second clone vector test", results[results.length - 1], new String(Hex.encode(resBuf)));
        }
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

    private void vectorTest(
        Digest digest,
        int count,
        byte[] resBuf,
        byte[] input,
        byte[] expected)
    {
        digest.update(input, 0, input.length);
        digest.doFinal(resBuf, 0);

        if (!areEqual(resBuf, expected))
        {
            fail("Vector " + count + " failed got " + new String(Hex.encode(resBuf)));
        }
    }

    private void offsetTest(
        Digest digest,
        int count,
        byte[] input,
        byte[] expected)
    {
        byte[] resBuf = new byte[expected.length + 11];

        digest.update(input, 0, input.length);
        digest.doFinal(resBuf, 11);

        if (!areEqual(Arrays.copyOfRange(resBuf, 11, resBuf.length), expected))
        {
            fail("Offset " + count + " failed got " + new String(Hex.encode(resBuf)));
        }
    }

    protected abstract Digest cloneDigest(Digest digest);

    protected Digest cloneDigest(byte[] encodedState)
    {
        throw new IllegalStateException("Unsupported");
    }

    //
    // optional tests
    //
    protected void millionATest(
        String expected)
    {
        byte[] resBuf = new byte[digest.getDigestSize()];

        for (int i = 0; i < 1000000; i++)
        {
            digest.update((byte)'a');
        }

        digest.doFinal(resBuf, 0);

        if (!areEqual(resBuf, Hex.decode(expected)))
        {
            fail("Million a's failed", expected, new String(Hex.encode(resBuf)));
        }
    }

    protected void sixtyFourKTest(
        String expected)
    {
        byte[] resBuf = new byte[digest.getDigestSize()];

        for (int i = 0; i < 65536; i++)
        {
            digest.update((byte)(i & 0xff));
        }

        digest.doFinal(resBuf, 0);

        if (!areEqual(resBuf, Hex.decode(expected)))
        {
            fail("64k test failed", expected, new String(Hex.encode(resBuf)));
        }
    }

    static void checkDigestReset(final SimpleTest test, final Digest pDigest)
    {
        int DATALEN = 100;
        /* Obtain some random data */
        final byte[] myData = new byte[DATALEN];
        final SecureRandom myRandom = new SecureRandom();
        myRandom.nextBytes(myData);

        /* Update and finalise digest */
        final int myHashLen = pDigest.getDigestSize();
        final byte[] myFirst = new byte[myHashLen];
        pDigest.update(myData, 0, DATALEN);
        pDigest.doFinal(myFirst, 0);


        /* Reuse the digest */
        final byte[] mySecond = new byte[myHashLen];
        pDigest.update(myData, 0, DATALEN);
        pDigest.doFinal(mySecond, 0);

        /* Check that we have the same result */
        if (!java.util.Arrays.equals(myFirst, mySecond))
        {
            throw new TestFailedException(SimpleTestResult.failed(test, "Digest " + pDigest.getAlgorithmName() + " does not reset properly on doFinal()"));
        }
    }

    static void implTestExceptionsAndParametersDigest(final SimpleTest test, final Digest pDigest, final int digestsize)
    {
        if (pDigest.getDigestSize() != digestsize)
        {
            test.fail(pDigest.getAlgorithmName() + ": digest size is not correct");
        }

        try
        {
            pDigest.update(new byte[1], 1, 1);
            test.fail(pDigest.getAlgorithmName() + ": input for update is too short");
        }
        catch (DataLengthException e)
        {
            //expected
        }

        try
        {
            pDigest.doFinal(new byte[pDigest.getDigestSize() - 1], 2);
            test.fail(pDigest.getAlgorithmName() + ": output for dofinal is too short");
        }
        catch (OutputLengthException e)
        {
            //expected
        }
    }

    static void implTestVectorsDigest(SimpleTest test, ExtendedDigest digest, String path, String filename)
        throws Exception
    {
        Random random = new Random();
        InputStream src = TestResourceFinder.findTestResource(path, filename);
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line;
        HashMap<String, String> map = new HashMap<String, String>();
        while ((line = bin.readLine()) != null)
        {
            int a = line.indexOf('=');
            if (a < 0)
            {
                int count = Integer.parseInt((String)map.get("Count"));
                if (count != 21)
                {
                    continue;
                }
                byte[] ptByte = Hex.decode((String)map.get("Msg"));
                byte[] expected = Hex.decode((String)map.get("MD"));

                byte[] hash = new byte[digest.getDigestSize()];

                digest.update(ptByte, 0, ptByte.length);
                digest.doFinal(hash, 0);
                if (!Arrays.areEqual(hash, expected))
                {
                    mismatch(test, "Keystream " + map.get("Count"), (String)map.get("MD"), hash);
                }

                if (ptByte.length > 1)
                {
                    int split = random.nextInt(ptByte.length - 1) + 1;
                    digest.update(ptByte, 0, split);
                    digest.update(ptByte, split, ptByte.length - split);
                    digest.doFinal(hash, 0);
                    if (!Arrays.areEqual(hash, expected))
                    {
                        mismatch(test, "Keystream " + map.get("Count"), (String)map.get("MD"), hash);
                    }
                }

                map.clear();
            }
            else
            {
                map.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
        }
    }

    private static void mismatch(SimpleTest test, String name, String expected, byte[] found)
    {
        test.fail("mismatch on " + name, expected, new String(Hex.encode(found)));
    }

    /**
     * Check xof.
     *
     * @param pXof       the xof
     * @param DATALEN    DataLength
     * @param PARTIALLEN Partial length
     */
    public static void checkXof(final Xof pXof, int DATALEN, int PARTIALLEN, SecureRandom random, SimpleTest test)
    {
        /* Create the data */
        final byte[] myData = new byte[DATALEN];
        random.nextBytes(myData);

        /* Update the Xof with the data */
        pXof.update(myData, 0, DATALEN);

        /* Extract Xof as single block */
        final byte[] myFull = new byte[DATALEN];
        pXof.doFinal(myFull, 0, DATALEN);

        /* Update the Xof with the data */
        pXof.update(myData, 0, DATALEN);
        final byte[] myPart = new byte[DATALEN];

        /* Create the xof as partial blocks */
        for (int myPos = 0; myPos < DATALEN; myPos += PARTIALLEN)
        {
            final int myLen = Math.min(PARTIALLEN, DATALEN - myPos);
            pXof.doOutput(myPart, myPos, myLen);
        }
        pXof.doFinal(myPart, 0, 0);

        /* Check that they are identical */
        if (!Arrays.areEqual(myPart, myFull))
        {
            test.fail(pXof.getAlgorithmName() + ": Mismatch on partial vs full xof");
        }
    }
}
