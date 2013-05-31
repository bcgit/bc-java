package org.bouncycastle.crypto.test;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.AESLightEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 * Test vectors from the NIST standard tests and Brian Gladman's vector set
 * <a href="http://fp.gladman.plus.com/cryptography_technology/rijndael/">
 * http://fp.gladman.plus.com/cryptography_technology/rijndael/</a>
 */
public class AESVectorFileTest
    implements Test
{

    private int countOfTests = 0;
    private int testNum = 0;

    protected BlockCipher createNewEngineForTest()
    {
        return new AESEngine();
    }

    private Test[] readTestVectors(InputStream inStream)
    {
        // initialize key, plaintext, ciphertext = null
        // read until find BLOCKSIZE=
        // return if not 128
        // read KEYSIZE= or ignore
        // loop
        // read a line
        // if starts with BLOCKSIZE=
        // parse the rest. return if not 128
        // if starts with KEY=
        // parse the rest and set KEY
        // if starts with PT=
        // parse the rest and set plaintext
        // if starts with CT=
        // parse the rest and set ciphertext
        // if starts with TEST= or end of file
        // if key, plaintext, ciphertext are all not null
        // save away their values as the next test
        // until end of file
        List   tests = new ArrayList();
        String key = null;
        String plaintext = null;
        String ciphertext = null;

        BufferedReader in = new BufferedReader(new InputStreamReader(inStream));

        try
        {
            String line = in.readLine();

            while (line != null)
            {
                line = line.trim().toLowerCase();
                if (line.startsWith("blocksize="))
                {
                    int i = 0;
                    try
                    {
                        i = Integer.parseInt(line.substring(10).trim());
                    }
                    catch (Exception e)
                    {
                    }
                    if (i != 128)
                    {
                        return null;
                    }
                }
                else if (line.startsWith("keysize="))
                {
                    int i = 0;
                    try
                    {
                        i = Integer.parseInt(line.substring(10).trim());
                    }
                    catch (Exception e)
                    {
                    }
                    if ((i != 128) && (i != 192) && (i != 256))
                    {
                        return null;
                    }
                }
                else if (line.startsWith("key="))
                {
                    key = line.substring(4).trim();
                }
                else if (line.startsWith("pt="))
                {
                    plaintext = line.substring(3).trim();
                }
                else if (line.startsWith("ct="))
                {
                    ciphertext = line.substring(3).trim();
                }
                else if (line.startsWith("test="))
                {
                    if ((key != null) && (plaintext != null)
                            && (ciphertext != null))
                    {
                        tests.add(new BlockCipherVectorTest(testNum++,
                                createNewEngineForTest(), new KeyParameter(Hex
                                        .decode(key)), plaintext, ciphertext));
                    }
                }

                line = in.readLine();
            }
            try
            {
                in.close();
            }
            catch (IOException e)
            {
            }
        }
        catch (IOException e)
        {
        }
        if ((key != null) && (plaintext != null) && (ciphertext != null))
        {
            tests.add(new BlockCipherVectorTest(testNum++,
                    createNewEngineForTest(),
                    new KeyParameter(Hex.decode(key)), plaintext, ciphertext));
        }
        return (Test[])(tests.toArray(new Test[tests.size()]));
    }

    public String getName()
    {
        return "AES";
    }

    private TestResult performTestsFromZipFile(File zfile)
    {
        try
        {
            ZipFile inZip = new ZipFile(zfile);
            for (Enumeration files = inZip.entries(); files.hasMoreElements();)
            {
                Test[] tests = null;
                try
                {
                    tests = readTestVectors(inZip
                            .getInputStream((ZipEntry)(files.nextElement())));
                }
                catch (Exception e)
                {
                    return new SimpleTestResult(false, getName() + ": threw "
                            + e);
                }
                if (tests != null)
                {
                    for (int i = 0; i != tests.length; i++)
                    {
                        TestResult res = tests[i].perform();
                        countOfTests++;

                        if (!res.isSuccessful())
                        {
                            return res;
                        }
                    }
                }
            }
            inZip.close();
            return new SimpleTestResult(true, getName() + ": Okay");
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": threw " + e);
        }
    }

    private static final String[] zipFileNames = { "rijn.tv.ecbnk.zip",
            "rijn.tv.ecbnt.zip", "rijn.tv.ecbvk.zip", "rijn.tv.ecbvt.zip" };

    public TestResult perform()
    {
        countOfTests = 0;
        for (int i = 0; i < zipFileNames.length; i++)
        {
            File inf = new File(zipFileNames[i]);
            TestResult res = performTestsFromZipFile(inf);
            if (!res.isSuccessful())
            {
                return res;
            }
        }
        return new SimpleTestResult(true, getName() + ": " + countOfTests
                + " performed Okay");
    }

    public static void main(String[] args)
    {
        AESVectorFileTest test = new AESVectorFileTest();
        TestResult result = test.perform();
        System.out.println(result);

        test = new AESLightVectorFileTest();
        result = test.perform();
        System.out.println(result);

        test = new AESFastVectorFileTest();
        result = test.perform();
        System.out.println(result);

    }

    private static class AESLightVectorFileTest extends AESVectorFileTest
    {
        protected BlockCipher createNewEngineForTest()
        {
            return new AESLightEngine();
        }

        public String getName()
        {
            return "AESLight";
        }

    }

    private static class AESFastVectorFileTest extends AESVectorFileTest
    {
        protected BlockCipher createNewEngineForTest()
        {
            return new AESFastEngine();
        }

        public String getName()
        {
            return "AESFast";
        }

    }
}
