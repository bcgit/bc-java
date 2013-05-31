package org.bouncycastle.jce.provider.test;

import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.Security;

/**
 * basic test class for Camellia
 */
public class CamelliaTest
    extends BaseBlockCipherTest
{
    static String[] cipherTests =
    {
        "128",
        "0123456789abcdeffedcba9876543210",
        "0123456789abcdeffedcba9876543210",
        "67673138549669730857065648eabe43",
        "192",
        "0123456789abcdeffedcba98765432100011223344556677",
        "0123456789abcdeffedcba9876543210",
        "b4993401b3e996f84ee5cee7d79b09b9",
        "256",
        "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
        "0123456789abcdeffedcba9876543210",
        "9acc237dff16d76c20ef7c919e3a7509",
    };

    public CamelliaTest()
    {
        super("Camellia");
    }

    public void test(
        int         strength,
        byte[]      keyBytes,
        byte[]      input,
        byte[]      output)
        throws Exception
    {
        Key key;
        Cipher in, out;
        CipherInputStream cIn;
        CipherOutputStream cOut;
        ByteArrayInputStream bIn;
        ByteArrayOutputStream bOut;

        key = new SecretKeySpec(keyBytes, "Camellia");

        in = Cipher.getInstance("Camellia/ECB/NoPadding", "BC");
        out = Cipher.getInstance("Camellia/ECB/NoPadding", "BC");

        try
        {
            out.init(Cipher.ENCRYPT_MODE, key);
        }
        catch (Exception e)
        {
            fail("Camellia failed initialisation - " + e.toString(), e);
        }

        try
        {
            in.init(Cipher.DECRYPT_MODE, key);
        }
        catch (Exception e)
        {
            fail("Camellia failed initialisation - " + e.toString(), e);
        }

        //
        // encryption pass
        //
        bOut = new ByteArrayOutputStream();

        cOut = new CipherOutputStream(bOut, out);

        try
        {
            for (int i = 0; i != input.length / 2; i++)
            {
                cOut.write(input[i]);
            }
            cOut.write(input, input.length / 2, input.length - input.length / 2);
            cOut.close();
        }
        catch (IOException e)
        {
            fail("Camellia failed encryption - " + e.toString(), e);
        }

        byte[]    bytes;

        bytes = bOut.toByteArray();

        if (!areEqual(bytes, output))
        {
            fail("Camellia failed encryption - expected " + new String(Hex.encode(output)) + " got " + new String(Hex.encode(bytes)));
        }

        //
        // decryption pass
        //
        bIn = new ByteArrayInputStream(bytes);

        cIn = new CipherInputStream(bIn, in);

        try
        {
            DataInputStream dIn = new DataInputStream(cIn);

            bytes = new byte[input.length];

            for (int i = 0; i != input.length / 2; i++)
            {
                bytes[i] = (byte)dIn.read();
            }
            dIn.readFully(bytes, input.length / 2, bytes.length - input.length / 2);
        }
        catch (Exception e)
        {
            fail("Camellia failed encryption - " + e.toString(), e);
        }

        if (!areEqual(bytes, input))
        {
            fail("Camellia failed decryption - expected " + new String(Hex.encode(input)) + " got " + new String(Hex.encode(bytes)));
        }
    }

    public void performTest()
        throws Exception
    {
        for (int i = 0; i != cipherTests.length; i += 4)
        {
            test(Integer.parseInt(cipherTests[i]),
                            Hex.decode(cipherTests[i + 1]),
                            Hex.decode(cipherTests[i + 2]),
                            Hex.decode(cipherTests[i + 3]));
        }

        byte[]  kek1 = Hex.decode("000102030405060708090a0b0c0d0e0f");
        byte[]  in1 = Hex.decode("00112233445566778899aabbccddeeff");
        byte[]  out1 = Hex.decode("635d6ac46eedebd3a7f4a06421a4cbd1746b24795ba2f708");

        wrapTest(1, "CamelliaWrap", kek1, in1, out1);

        String[] oids = {
                NTTObjectIdentifiers.id_camellia128_cbc.getId(),
                NTTObjectIdentifiers.id_camellia192_cbc.getId(),
                NTTObjectIdentifiers.id_camellia256_cbc.getId()
        };

        String[] names = {
                "Camellia/CBC/PKCS7Padding",
                "Camellia/CBC/PKCS7Padding",
                "Camellia/CBC/PKCS7Padding"
        };

        oidTest(oids, names, 1);

        String[] wrapOids = {
                NTTObjectIdentifiers.id_camellia128_wrap.getId(),
                NTTObjectIdentifiers.id_camellia192_wrap.getId(),
                NTTObjectIdentifiers.id_camellia256_wrap.getId()
        };

        wrapOidTest(wrapOids, "CamelliaWrap");
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new CamelliaTest());
    }
}
