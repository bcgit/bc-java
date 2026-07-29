package org.bouncycastle.crypto.test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.engines.SM9Engine;
import org.bouncycastle.crypto.kems.SM9KEMExtractor;
import org.bouncycastle.crypto.kems.SM9KEMGenerator;
import org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9EncPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9EncPublicKeyParameters;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomBigInteger;

/**
 * Known-answer test for the SM9 key encapsulation mechanism (GM/T 0044.4-2016)
 * against the GM/T 0044.5-2016 Part 5, Annex C vector (crypto/sm9/sm9_kem.txt):
 * the encapsulation C and shared key K are reproduced byte-for-byte, and the
 * decapsulation recovers K.
 */
public class SM9KEMTest
    extends SimpleTest
{
    public String getName()
    {
        return "SM9KEM";
    }

    private Map loadVectors(String fileName)
        throws Exception
    {
        Map m = new HashMap();
        BufferedReader br = new BufferedReader(
            new InputStreamReader(TestResourceFinder.findTestResource("crypto/sm9", fileName)));
        try
        {
            String line;
            while ((line = br.readLine()) != null)
            {
                line = line.trim();
                if (line.length() == 0 || line.startsWith("#"))
                {
                    continue;
                }
                int eq = line.indexOf('=');
                if (eq > 0)
                {
                    m.put(line.substring(0, eq).trim(), line.substring(eq + 1).trim());
                }
            }
        }
        finally
        {
            br.close();
        }
        return m;
    }

    private byte[] hex(Map v, String key)
    {
        return Hex.decode((String)v.get(key));
    }

    public void performTest()
        throws Exception
    {
        Map v = loadVectors("sm9_kem.txt");
        BigInteger ke = new BigInteger((String)v.get("ke"), 16);
        byte[] identity = hex(v, "IDB");
        int klen = Integer.parseInt((String)v.get("klen_bits"));

        SM9EncMasterPrivateKeyParameters master = new SM9EncMasterPrivateKeyParameters(ke);
        SM9EncPublicKeyParameters recipient = master.getPublicKeyParameters().getUserPublicKey(identity);

        SM9KEMGenerator gen = new SM9KEMGenerator(klen, new TestRandomBigInteger(256, hex(v, "r")));
        SecretWithEncapsulation enc = gen.generateEncapsulated(recipient);
        isTrue("SM9 KEM key K", Arrays.areEqual(enc.getSecret(), hex(v, "K")));
        isTrue("SM9 KEM encapsulation C",
            Arrays.areEqual(enc.getEncapsulation(), Arrays.concatenate(hex(v, "C_x"), hex(v, "C_y"))));

        SM9EncPrivateKeyParameters userKey = master.generateUserKey(identity, SM9EncMasterPrivateKeyParameters.HID);
        SM9KEMExtractor extractor = new SM9KEMExtractor(userKey, klen);
        isTrue("SM9 KEM decapsulation", Arrays.areEqual(extractor.extractSecret(enc.getEncapsulation()), hex(v, "K")));

        // a key-exchange user key must not decapsulate - the two usages are kept
        // on separate keys so an exchange peer never gains a pairing oracle on a
        // key that also decrypts
        SM9EncPrivateKeyParameters exchangeKey = master.generateExchangeKey(identity);
        try
        {
            new SM9KEMExtractor(exchangeKey, klen);
            fail("SM9KEMExtractor accepted a key-exchange user key");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("SM9 KEM decapsulation requires an encryption user key, not a key-exchange key".equals(e.getMessage()));
        }
        try
        {
            new SM9Engine().init(false, exchangeKey);
            fail("SM9Engine accepted a key-exchange user key for decryption");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("SM9 decryption requires an encryption user key, not a key-exchange key".equals(e.getMessage()));
        }

        // a non-positive key length must be rejected at construction: the KDF would
        // produce no output and the all-zero retry loop would never terminate (the
        // same shape as the SM9Engine empty-message stream-mode loop)
        try
        {
            new SM9KEMGenerator(0, new TestRandomBigInteger(256, hex(v, "r")));
            fail("SM9KEMGenerator accepted keyLenBits = 0");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("keyLenBits must be positive".equals(e.getMessage()));
        }
        try
        {
            new SM9KEMExtractor(userKey, -8);
            fail("SM9KEMExtractor accepted negative keyLenBits");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("keyLenBits must be positive".equals(e.getMessage()));
        }
    }

    public static void main(String[] args)
    {
        runTest(new SM9KEMTest());
    }
}
