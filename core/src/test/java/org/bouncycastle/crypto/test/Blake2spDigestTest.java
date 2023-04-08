package org.bouncycastle.crypto.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;

import junit.framework.TestCase;
import org.bouncycastle.crypto.digests.Blake2spDigest;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class Blake2spDigestTest
    extends TestCase
{
    public void testKATfile()
            throws Exception
    {
        Blake2spDigest digest;
        InputStream src = TestResourceFinder.findTestResource("crypto", "Blake2KAT.txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));

        String line = null;
        String name = null;
        String input = null;
        String key = null;
        String output = null;
        byte[] message;
        byte[] hash = new byte[32];

        while ((line = bin.readLine()) != null)
        {
            line = line.trim();

            if ( line.startsWith("#"))
            {
                if( name.equals("blake2sp"))
                {
                    digest = new Blake2spDigest(Hex.decode(key));
                    message = Hex.decode(input);
                    digest.update(message, 0, message.length);
                    digest.doFinal(hash, 0);
                    assertTrue ("BLAKE2sp mismatch on test vector: " + output + ", " + Hex.toHexString(hash),
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
        byte[] key = Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        String res = "8dbcc0589a3d17296a7a58e2f1eff0e2aa4210b58d1f88b86d7ba5f29dd3b583";
        String in = "000102";
        byte[] output = new byte[32];
        Blake2spDigest digest = new Blake2spDigest(key);
        digest.update(Hex.decode("9999"+in), 2, 3);
        digest.doFinal(output, 0);
        assertTrue("BLAKE2sp mismatch on update offset", Arrays.areEqual(Hex.decode(res), output));

        Arrays.fill(output, (byte)0);
        output = Arrays.concatenate(Hex.decode("9999"), output);
        digest.update(Hex.decode(in), 0, 3);
        digest.doFinal(output, 2);
        assertTrue("BLAKE2sp mismatch on doFinal offset", Arrays.areEqual(Hex.decode("9999" + res), output));


    }
    public void testReset()
    {
        byte[] key = new byte[32];
        byte[] buf = new byte[256];
        byte[][] stepOne = new byte[256][32];

        for (int i = 0; i < 32; i++)
        {
            key[i] = (byte) i;
        }
        for (int i = 0; i < 256; i++)
        {
            buf[i] = (byte) i;
        }

        Blake2spDigest digest = new Blake2spDigest(key);
        for (int step = 1; step < 64; step++)
        {
            for (int i = 0; i < 256; i++)
            {
                int mlen = i;
                int pOffset = 0;
                byte[] hash = new byte[32];

                while(mlen >= step)
                {
                    digest.update(buf, pOffset, step);
                    mlen -= step;
                    pOffset += step;
                }

                digest.update(buf, pOffset, mlen);

                digest.doFinal(hash, 0);
                if(step == 1)
                {
                    System.arraycopy(hash, 0, stepOne[i], 0, hash.length);
                }
                else
                {
                    assertTrue("BLAKE2s mismatch on test vector: ", Arrays.areEqual(stepOne[i], hash));
                }
            }
        }
    }
}
