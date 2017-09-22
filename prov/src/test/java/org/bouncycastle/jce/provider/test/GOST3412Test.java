package org.bouncycastle.jce.provider.test;

import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.security.Key;
import java.security.Security;

/**
 * basic test class for the GOST3412 cipher
 */
public class GOST3412Test
    extends SimpleTest {
    static String[] cipherTests =
        {
            "256",
            "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
            "1122334455667700ffeeddccbbaa9988",
            "7f679d90bebc24305a468d42b9d4edcd"
        };

    public String getName() {
        return "GOST3412";
    }

    public void testECB(
        int strength,
        byte[] keyBytes,
        byte[] input,
        byte[] output)
        throws Exception {
        Key key;
        Cipher in, out;
        CipherInputStream cIn;
        CipherOutputStream cOut;
        ByteArrayInputStream bIn;
        ByteArrayOutputStream bOut;

        key = new SecretKeySpec(keyBytes, "GOST3412");

        in = Cipher.getInstance("GOST3412/ECB/NoPadding", "BC");
        out = Cipher.getInstance("GOST3412/ECB/NoPadding", "BC");
        out.init(Cipher.ENCRYPT_MODE, key);
        in.init(Cipher.DECRYPT_MODE, key);

        //
        // encryption pass
        //
        bOut = new ByteArrayOutputStream();

        cOut = new CipherOutputStream(bOut, out);

        for (int i = 0; i != input.length / 2; i++) {
            cOut.write(input[i]);
        }
        cOut.write(input, input.length / 2, input.length - input.length / 2);
        cOut.close();

        byte[] bytes;

        bytes = bOut.toByteArray();

        if (!areEqual(bytes, output)) {
            fail("GOST3412 failed encryption - expected " + new String(Hex.encode(output)) + " got " + new String(Hex.encode(bytes)));
        }

        //
        // decryption pass
        //
        bIn = new ByteArrayInputStream(bytes);

        cIn = new CipherInputStream(bIn, in);

        DataInputStream dIn = new DataInputStream(cIn);

        bytes = new byte[input.length];

        for (int i = 0; i != input.length / 2; i++) {
            bytes[i] = (byte) dIn.read();
        }
        dIn.readFully(bytes, input.length / 2, bytes.length - input.length / 2);

        if (!areEqual(bytes, input)) {
            fail("GOST3412 failed decryption - expected " + new String(Hex.encode(input)) + " got " + new String(Hex.encode(bytes)));
        }
    }

    public void testMac() throws Exception {
        Mac mac = Mac.getInstance("GOST3412MAC", "BC");

        mac.init(new SecretKeySpec(Hex.decode("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"), "GOST3412MAC"));
        byte[][] inputs = new byte[][]{
            Hex.decode("1122334455667700ffeeddccbbaa9988"),
            Hex.decode("00112233445566778899aabbcceeff0a"),
            Hex.decode("112233445566778899aabbcceeff0a00"),
            Hex.decode("2233445566778899aabbcceeff0a0011"),
        };

        for (byte[] input : inputs) {
            mac.update(input, 0, input.length);
        }

        byte[] out = new byte[8];

        mac.doFinal(out, 0);


        if (!Arrays.areEqual(Hex.decode("336f4d296059fbe3"), mac.doFinal(Hex.decode(out)))) {
            fail("mac test falied.");
        }
    }

    public void performTest()
        throws Exception {


        testECB(Integer.parseInt(cipherTests[0]),
            Hex.decode(cipherTests[1]),
            Hex.decode(cipherTests[2]),
            Hex.decode(cipherTests[3]));

        testMac();
    }

    public static void main(
        String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new GOST3412Test());
    }
}
