package org.bouncycastle.jce.provider.test;

import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.generators.Poly1305KeyGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestFailedException;

public class Poly1305Test
    extends SimpleTest
{
    private static final byte[] MASTER_KEY = Hex
        .decode("01bcb20bfc8b6e03609ddd09f44b060f"+"95cc0e44d0b79a8856afcae1bec4fe3c");

    public String getName()
    {
        return "Poly1305";
    }

    public void performTest()
        throws Exception
    {
        checkRawPoly1305();
        checkRegistrations();
    }

    private void checkRegistrations()
        throws Exception
    {
        List missingMacs = new ArrayList();
        List missingKeyGens = new ArrayList();

        String[] ciphers = new String[]{"AES", "NOEKEON", "Twofish", "CAST6", "SEED", "Serpent", "SM4", "RC6", "CAMELLIA"};
        String[] macs = new String[]{
            "4bb5e21dd13001ed5faccfcfdaf8a854",
            "6d601be3d5ebbb9972a64ed3223d913d",
            "211195296d9afc7b35a1223a79487c87",
            "f328857a1b653684e73760c804c55b1d",
            "21cd8adb23ca84eb4dbb12780595bf28",
            "c218102702d8a2ee5c9ef9000e91454d",
            "9bb04be6a1c314a9054ae3c94d3c941b",
            "db86de7b1fcae429753d68b1263d7ca0",
            "11918174f33a2f278fb86554da094112"};

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
            // Poly1305 is defined over 128 bit block ciphers
            if (blocksize == 16)
            {
                String macName = "Poly1305-" + cipherName;
                String macNameAlt = "Poly1305" + cipherName;

                // Check we have a Poly1305 registered for each name
                checkMac(macName, missingMacs, missingKeyGens, macs[i]);
                checkMac(macNameAlt, missingMacs, missingKeyGens, macs[i]);
            }
        }
        if (missingMacs.size() != 0)
        {
            fail("Did not find Poly1305 registrations for the following ciphers: " + missingMacs);
        }
        if (missingKeyGens.size() != 0)
        {
            fail("Did not find Poly1305 KeyGenerator registrations for the following macs: " + missingKeyGens);
        }
    }

    private void checkRawPoly1305()
        throws Exception
    {
        checkMac("Poly1305", "e8bd1466eaf442dd71598370c1e34392");
    }

    private void checkMac(String name, String macOutput)
        throws Exception
    {
        KeyGenerator kg = KeyGenerator.getInstance(name);
        SecretKey key = kg.generateKey();

        try
        {
            Poly1305KeyGenerator.checkKey(key.getEncoded());
        }
        catch (IllegalArgumentException e)
        {
            fail("Generated key for algo " + name + " does not match required Poly1305 format.");
        }

        Mac mac = Mac.getInstance(name);
        mac.init(new SecretKeySpec(MASTER_KEY, name));
        mac.update(new byte[128]);
        byte[] bytes = mac.doFinal();

        if (!Arrays.areEqual(bytes, Hex.decode(macOutput)))
        {
            fail("wrong mac value computed for " + name, macOutput, new String(Hex.encode(bytes)));
        }
    }

    private void checkMac(String name, List missingMacs, List missingKeyGens, String macOutput)
    {
        try
        {
            try
            {
                KeyGenerator kg = KeyGenerator.getInstance(name);
                SecretKey key = kg.generateKey();

                try
                {
                    Poly1305KeyGenerator.checkKey(key.getEncoded());
                }
                catch (IllegalArgumentException e)
                {
                    fail("Generated key for algo " + name + " does not match required Poly1305 format.");
                }

                try
                {
                    Mac mac = Mac.getInstance(name);
                    mac.init(new SecretKeySpec(MASTER_KEY, name), new IvParameterSpec(new byte[16]));
                    mac.update(new byte[128]);
                    byte[] bytes = mac.doFinal();

                    if (!Arrays.areEqual(bytes, Hex.decode(macOutput)))
                    {
                        fail("wrong mac value computed for " + name, macOutput, new String(Hex.encode(bytes)));
                    }
                }
                catch (NoSuchAlgorithmException e)
                {
                    missingMacs.add(name);
                }

            }
            catch (NoSuchAlgorithmException e)
            {
                missingKeyGens.add(name);
            }
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

        runTest(new Poly1305Test());
    }
}