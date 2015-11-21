package org.bouncycastle.jce.provider.test;

import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestFailedException;

public class GMacTest
    extends SimpleTest
{
    public String getName()
    {
        return "GMac";
    }

    public void performTest()
        throws Exception
    {
        checkRegistrations();
    }

    private void checkRegistrations()
        throws Exception
    {
        List missingMacs = new ArrayList();
        List missingKeyGens = new ArrayList();

        String[] ciphers = new String[] { "AES", "NOEKEON", "Twofish", "CAST6", "SEED", "Tnepres", "Serpent", "SM4", "RC6", "CAMELLIA" };
        String[] macs = new String[]
            {
                "a52308801b32d4770c701ace9b826f12",
                "cf11dacaf6024a78dba76b256e23caab",
                "13db7c428e5a7128149b5ec782d07fac",
                "d13a33e78e48b274bf7d64bf9aecdb82",
                "d05d550054735c6e7e01b6981fc14b4e",
                "4a34dfe4f5410afd7c40b1e110377a73",
                "80c3cc898899e41fd4e21c6c1261fedb",
                "d394f3d12bec3cf6c5302265ecab9af1",
                "d9f597c96b41f641da6c83d4760f543b",
                "371ad8cc920c6bda2a26d8f237bd446b"
            };

        for (int i = 0; i < ciphers.length; i++)
        {
            String cipherName = ciphers[i];
            Cipher cipher;
            try
            {
                cipher = Cipher.getInstance(cipherName, "BC");
            }
            catch (Exception e)
            {
                System.err.println(cipherName + ": " + e.getMessage());
                continue;
            }
            int blocksize;
            try
            {
                blocksize = cipher.getBlockSize();
            }
            catch (Exception e)
            {
                System.err.println(cipherName + ": " + e.getMessage());
                continue;
            }
            // GCM is defined over 128 bit block ciphers
            if (blocksize == 16)
            {
                String macName = cipherName + "-GMAC";
                String macNameAlt = cipherName + "GMAC";

                // Check we have a GMAC registered for each name
                checkMac(macName, missingMacs, missingKeyGens, macs[i]);
                checkMac(macNameAlt, missingMacs, missingKeyGens, macs[i]);
            }
        }
        if (missingMacs.size() != 0)
        {
            fail("Did not find GMAC registrations for the following ciphers: " + missingMacs);
        }
        if (missingKeyGens.size() != 0)
        {
            fail("Did not find GMAC KeyGenerator registrations for the following macs: " + missingKeyGens);
        }
    }

    private void checkMac(String name, List missingMacs, List missingKeyGens, String macOutput)
    {
        try
        {
            Mac mac = Mac.getInstance(name);

            mac.init(new SecretKeySpec(new byte[mac.getMacLength()], mac.getAlgorithm()), new IvParameterSpec(
                new byte[16]));
            mac.update(new byte[128]);
            byte[] bytes = mac.doFinal();

            if (!Arrays.areEqual(bytes, Hex.decode(macOutput)))
            {
                fail("wrong mac value computed for " + name + " " + Hex.toHexString(bytes));
            }

            try
            {
                KeyGenerator kg = KeyGenerator.getInstance(name);
                kg.generateKey();
            }
            catch (NoSuchAlgorithmException e)
            {
                missingKeyGens.add(name);
            }
        }
        catch (NoSuchAlgorithmException e)
        {
            missingMacs.add(name);
        }
        catch (TestFailedException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            fail("Unexpected error", e);
        }
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new GMacTest());
    }
}