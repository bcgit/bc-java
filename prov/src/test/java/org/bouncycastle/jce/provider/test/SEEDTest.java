package org.bouncycastle.jce.provider.test;

import org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
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
 * basic test class for SEED
 */
public class SEEDTest
    extends BaseBlockCipherTest
{
    static String[] cipherTests =
    {
        "128",
        "28DBC3BC49FFD87DCFA509B11D422BE7",
        "B41E6BE2EBA84A148E2EED84593C5EC7",
        "9B9B7BFCD1813CB95D0B3618F40F5122"
    };

    public SEEDTest()
    {
        super("SEED");
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

        key = new SecretKeySpec(keyBytes, "SEED");

        in = Cipher.getInstance("SEED/ECB/NoPadding", "BC");
        out = Cipher.getInstance("SEED/ECB/NoPadding", "BC");

        try
        {
            out.init(Cipher.ENCRYPT_MODE, key);
        }
        catch (Exception e)
        {
            fail("SEED failed initialisation - " + e.toString(), e);
        }

        try
        {
            in.init(Cipher.DECRYPT_MODE, key);
        }
        catch (Exception e)
        {
            fail("SEED failed initialisation - " + e.toString(), e);
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
            fail("SEED failed encryption - " + e.toString(), e);
        }

        byte[]    bytes;

        bytes = bOut.toByteArray();

        if (!areEqual(bytes, output))
        {
            fail("SEED failed encryption - expected " + new String(Hex.encode(output)) + " got " + new String(Hex.encode(bytes)));
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
            fail("SEED failed encryption - " + e.toString(), e);
        }

        if (!areEqual(bytes, input))
        {
            fail("SEED failed decryption - expected " + new String(Hex.encode(input)) + " got " + new String(Hex.encode(bytes)));
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
        byte[]  out1 = Hex.decode("bf71f77138b5afea05232a8dad54024e812dc8dd7d132559");

        wrapTest(1, "SEEDWrap", kek1, in1, out1);

        String[] oids = {
                KISAObjectIdentifiers.id_seedCBC.getId()
        };

        String[] names = {
                "SEED/CBC/PKCS7Padding"
        };

        oidTest(oids, names, 1);

        String[] wrapOids = {
                KISAObjectIdentifiers.id_npki_app_cmsSeed_wrap.getId()
        };

        wrapOidTest(wrapOids, "SEEDWrap");
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new SEEDTest());
    }
}
