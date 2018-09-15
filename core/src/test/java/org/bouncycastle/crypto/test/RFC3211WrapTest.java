package org.bouncycastle.crypto.test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.RFC3211WrapEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.prng.FixedSecureRandom;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Wrap Test based on RFC3211 test vectors
 */
public class RFC3211WrapTest
    extends SimpleTest
{
    SecureRandom r1 = new FixedSecureRandom(Hex.decode("C436F541"));

    SecureRandom r2 = new FixedSecureRandom(Hex.decode("FA060A45"));

    public String getName()
    {
        return "RFC3211Wrap";
    }

    private void wrapTest(
        int          id,
        BlockCipher  engine,
        byte[]       kek,
        byte[]       iv,
        SecureRandom rand,
        byte[]       in,
        byte[]       out)
        throws Exception
    {
        Wrapper wrapper = new RFC3211WrapEngine(engine);

        wrapper.init(true, new ParametersWithRandom(new ParametersWithIV(new KeyParameter(kek), iv), rand));

        byte[]  cText = wrapper.wrap(in, 0, in.length);
        if (!Arrays.areEqual(cText, out))
        {
            fail("failed wrap test " + id  + " expected " + new String(Hex.encode(out)) + " got " + new String(Hex.encode(cText)));
        }

        wrapper.init(false, new ParametersWithIV(new KeyParameter(kek), iv));

        byte[]  pText = wrapper.unwrap(out, 0, out.length);
        if (!Arrays.areEqual(pText, in))
        {
            fail("rfailed unwrap test " + id  + " expected " + new String(Hex.encode(in)) + " got " + new String(Hex.encode(pText)));
        }
    }

    private void testCorruption()
        throws InvalidCipherTextException
    {
        byte[] kek = Hex.decode("D1DAA78615F287E6");
        byte[] iv = Hex.decode("EFE598EF21B33D6D");

        Wrapper wrapper = new RFC3211WrapEngine(new DESEngine());

        wrapper.init(false, new ParametersWithIV(new KeyParameter(kek), iv));

        byte[] block = Hex.decode("ff739D838C627C897323A2F8C436F541");
        encryptBlock(kek, iv, block);

        try
        {
            wrapper.unwrap(block, 0, block.length);

            fail("bad length not detected");
        }
        catch (InvalidCipherTextException e)
        {
            if (!e.getMessage().equals("wrapped key corrupted"))
            {
                fail("wrong exception on length");
            }
        }

        block = Hex.decode("08639D838C627C897323A2F8C436F541");
        testChecksum(kek, iv, block, wrapper);

        block = Hex.decode("08736D838C627C897323A2F8C436F541");
        testChecksum(kek, iv, block, wrapper);
        
        block = Hex.decode("08739D638C627C897323A2F8C436F541");
        testChecksum(kek, iv, block, wrapper);
    }

    private void testChecksum(byte[] kek, byte[] iv, byte[] block, Wrapper wrapper)
    {
        encryptBlock(kek, iv, block);

        try
        {
            wrapper.unwrap(block, 0, block.length);

            fail("bad checksum not detected");
        }
        catch (InvalidCipherTextException e)
        {
            if (!e.getMessage().equals("wrapped key corrupted"))
            {
                fail("wrong exception");
            }
        }
    }

    private void encryptBlock(byte[] key, byte[] iv, byte[] cekBlock)
    {
        BlockCipher engine = new CBCBlockCipher(new DESEngine());

        engine.init(true, new ParametersWithIV(new KeyParameter(key), iv));

        for (int i = 0; i < cekBlock.length; i += 8)
        {
            engine.processBlock(cekBlock, i, cekBlock, i);
        }

        for (int i = 0; i < cekBlock.length; i += 8)
        {
            engine.processBlock(cekBlock, i, cekBlock, i);
        }
    }

    public void performTest()
        throws Exception
    {
        wrapTest(1, new DESEngine(), Hex.decode("D1DAA78615F287E6"), Hex.decode("EFE598EF21B33D6D"), r1, Hex.decode("8C627C897323A2F8"), Hex.decode("B81B2565EE373CA6DEDCA26A178B0C10"));
        wrapTest(2, new DESedeEngine(), Hex.decode("6A8970BF68C92CAEA84A8DF28510858607126380CC47AB2D"), Hex.decode("BAF1CA7931213C4E"), r2,
                    Hex.decode("8C637D887223A2F965B566EB014B0FA5D52300A3F7EA40FFFC577203C71BAF3B"),
                    Hex.decode("C03C514ABDB9E2C5AAC038572B5E24553876B377AAFB82ECA5A9D73F8AB143D9EC74E6CAD7DB260C"));

        testCorruption();
        
        Wrapper          wrapper = new RFC3211WrapEngine(new DESEngine());
        ParametersWithIV params = new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]);
        byte[]           buf = new byte[16];

        try
        {
            wrapper.init(true, params);

            wrapper.unwrap(buf, 0, buf.length);

            fail("failed unwrap state test.");
        }
        catch (IllegalStateException e)
        {
            // expected
        }
        catch (InvalidCipherTextException e)
        {
            fail("unexpected exception: " + e, e);
        }

        try
        {
            wrapper.init(false, params);

            wrapper.wrap(buf, 0, buf.length);

            fail("failed unwrap state test.");
        }
        catch (IllegalStateException e)
        {
            // expected
        }

        //
        // short test
        //
        try
        {
            wrapper.init(false, params);

            wrapper.unwrap(buf, 0, buf.length / 2);

            fail("failed unwrap short test.");
        }
        catch (InvalidCipherTextException e)
        {
            // expected
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new RFC3211WrapTest());
    }
}
