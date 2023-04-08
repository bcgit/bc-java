package org.bouncycastle.crypto.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;

import junit.framework.TestCase;
import org.bouncycastle.crypto.digests.Blake2bpDigest;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class Blake2bpDigestTest
        extends TestCase
{

    public void testKATfile()
            throws Exception
    {
        Blake2bpDigest digest;
        InputStream src = TestResourceFinder.findTestResource("crypto", "Blake2KAT.txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));

        String line = null;
        String name = null;
        String input = null;
        String key = null;
        String output = null;
        byte[] message;
        byte[] hash = new byte[64];

        while ((line = bin.readLine()) != null)
        {
            line = line.trim();

            if ( line.startsWith("#"))
            {
                if( name.equals("blake2bp"))
                {
                    digest = new Blake2bpDigest(Hex.decode(key));
                    message = Hex.decode(input);
                    digest.update(message, 0, message.length);
                    digest.doFinal(hash, 0);
                    assertTrue ("BLAKE2bp mismatch on test vector: " + output + ", " + Hex.toHexString(hash),
                            Arrays.areEqual(Hex.decode(output), hash) );

                }
            }
            name = line;
            input = bin.readLine();
            key = bin.readLine();
            output = bin.readLine();
        }

    }
    public void testOffset()
    {

        byte[] key = Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
        String res = "30302c3fc999065d10dc982c8feef41bbb6642718f624af6e3eabea083e7fe785340db4b0897efff39cee1dc1eb737cd1eea0fe75384984e7d8f446faa683b80";
        String in = "000102";
        byte[] output = new byte[64];
        Blake2bpDigest digest = new Blake2bpDigest(key);
        digest.update(Hex.decode("9999"+in), 2, 3);
        digest.doFinal(output, 0);
        assertTrue("BLAKE2bp mismatch on update offset", Arrays.areEqual(Hex.decode(res), output));

        Arrays.fill(output, (byte)0);
        output = Arrays.concatenate(Hex.decode("9999"), output);
        digest.update(Hex.decode(in), 0, 3);
        digest.doFinal(output, 2);
        assertTrue("BLAKE2bp mismatch on doFinal offset", Arrays.areEqual(Hex.decode("9999" + res), output));
    }
    
    public void testReset()
    {
        byte[] key = new byte[64];
        byte[] buf = new byte[256];
        byte[][] stepOne = new byte[256][64];

        for (int i = 0; i < 64; i++)
        {
            key[i] = (byte) i;
        }
        for (int i = 0; i < 256; i++)
        {
            buf[i] = (byte) i;
        }

        Blake2bpDigest digest = new Blake2bpDigest(key);
        for (int step = 1; step < 128; step++)
        {
            for (int i = 0; i < 256; i++)
            {
                digest.reset();
                int mlen = i;
                int pOffset = 0;
                byte[] hash = new byte[64];

                while (mlen >= step)
                {
                    digest.update(buf, pOffset, step);
                    mlen -= step;
                    pOffset += step;
                }

                digest.update(buf, pOffset, mlen);

                digest.doFinal(hash, 0);

                if (step == 1)
                {
                    System.arraycopy(hash, 0, stepOne[i], 0, hash.length);
                }
                else
                {
                    assertTrue("BLAKE2b mismatch on test vector: ", Arrays.areEqual(stepOne[i], hash));
                }
            }
        }
    }
}
