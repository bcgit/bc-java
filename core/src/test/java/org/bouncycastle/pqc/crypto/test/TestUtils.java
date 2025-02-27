package org.bouncycastle.pqc.crypto.test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.SecureRandom;
import java.util.HashMap;

import junit.framework.Assert;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;

class TestUtils
{
    static boolean parseBoolean(String value)
    {
        return "true".equalsIgnoreCase(value);
    }

    public interface KeyGenerationOperation
    {
        AsymmetricCipherKeyPairGenerator getAsymmetricCipherKeyPairGenerator(int fileIndex, byte[] seed);

        byte[] getPublicKeyEncoded(AsymmetricKeyParameter pubParams);

        byte[] getPrivateKeyEncoded(AsymmetricKeyParameter privParams);
    }

    public static void testKeyGen(boolean enableFactory, String homeDir, String[] files, KeyGenerationOperation operation)
        throws IOException
    {
        for (int fileIndex = 0; fileIndex != files.length; fileIndex++)
        {
            String name = files[fileIndex];
            InputStream src = TestResourceFinder.findTestResource(homeDir, name);
            BufferedReader bin = new BufferedReader(new InputStreamReader(src));

            String line;
            HashMap<String, String> buf = new HashMap<String, String>();
            while ((line = bin.readLine()) != null)
            {
                line = line.trim();

                if (line.startsWith("#"))
                {
                    continue;
                }
                if (line.length() == 0)
                {
                    if (buf.size() > 0)
                    {
                        byte[] seed = Hex.decode((String)buf.get("seed"));
                        byte[] pk = Hex.decode((String)buf.get("pk"));
                        byte[] sk = Hex.decode((String)buf.get("sk"));

                        AsymmetricCipherKeyPairGenerator kpGen = operation.getAsymmetricCipherKeyPairGenerator(fileIndex, seed);

                        //
                        // Generate keys and test.
                        //
                        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();
                        AsymmetricKeyParameter pubParams, privParams;
                        if (enableFactory)
                        {
                            pubParams = PublicKeyFactory.createKey(
                                SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(kp.getPublic()));
                            privParams = PrivateKeyFactory.createKey(
                                PrivateKeyInfoFactory.createPrivateKeyInfo(kp.getPrivate()));
                        }
                        else
                        {
                            pubParams = kp.getPublic();
                            privParams = kp.getPrivate();
                        }

                        Assert.assertTrue(name + ": public key", Arrays.areEqual(pk, operation.getPublicKeyEncoded(pubParams)));
                        Assert.assertTrue(name + ": secret key", Arrays.areEqual(sk, operation.getPrivateKeyEncoded(privParams)));
                    }
                    buf.clear();
                    continue;
                }

                int a = line.indexOf("=");
                if (a > -1)
                {
                    buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
                }
            }
        }
    }
}
