package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.crypto.engines.DSTU7624Engine;
import org.bouncycastle.crypto.engines.GOST28147Engine;
import org.bouncycastle.crypto.engines.GOST3412_2015Engine;
import org.bouncycastle.crypto.engines.Grain128Engine;
import org.bouncycastle.crypto.engines.Grainv1Engine;
import org.bouncycastle.crypto.engines.HC128Engine;
import org.bouncycastle.crypto.engines.HC256Engine;
import org.bouncycastle.crypto.engines.ISAACEngine;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.engines.Salsa20Engine;
import org.bouncycastle.crypto.engines.VMPCEngine;
import org.bouncycastle.crypto.engines.VMPCKSA3Engine;
import org.bouncycastle.crypto.engines.XChaCha20Engine;
import org.bouncycastle.crypto.engines.XSalsa20Engine;
import org.bouncycastle.crypto.engines.Zuc128Engine;
import org.bouncycastle.crypto.engines.Zuc256Engine;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.G3413CFBBlockCipher;
import org.bouncycastle.crypto.modes.G3413CTRBlockCipher;
import org.bouncycastle.crypto.modes.G3413OFBBlockCipher;
import org.bouncycastle.crypto.modes.GCFBBlockCipher;
import org.bouncycastle.crypto.modes.GOFBBlockCipher;
import org.bouncycastle.crypto.modes.KCTRBlockCipher;
import org.bouncycastle.crypto.modes.OFBBlockCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.test.SimpleTest;

/**
 * processBytes() with the input and the output in the same array, the output starting before, at
 * and after the start of the input. Output that starts after the input and overlaps it used to
 * overwrite input that had not been read yet.
 */
public class StreamCipherOverlapTest
    extends SimpleTest
{
    private static final int IN_OFF = 7;
    private static final int LEN = 160;
    private static final int[] OUT_OFFS = new int[]{ 0, 3, 7, 8, 14, 16, 23, 100, IN_OFF + LEN - 1, IN_OFF + LEN };

    private abstract static class Source
    {
        final String name;
        final CipherParameters params;

        Source(String name, int keyLen, int ivLen)
        {
            this.name = name;

            KeyParameter key = new KeyParameter(fill(keyLen, 1));

            this.params = (ivLen == 0) ? (CipherParameters)key : new ParametersWithIV(key, fill(ivLen, 101));
        }

        abstract StreamCipher create();
    }

    private static byte[] fill(int len, int start)
    {
        byte[] b = new byte[len];
        for (int i = 0; i != len; i++)
        {
            b[i] = (byte)(start + 7 * i);
        }
        return b;
    }

    private static Source[] sources()
    {
        return new Source[]
        {
            new Source("SIC/AES", 16, 16)
            {
                StreamCipher create()
                {
                    return (StreamCipher)SICBlockCipher.newInstance(AESEngine.newInstance());
                }
            },
            new Source("CFB128/AES", 16, 16)
            {
                StreamCipher create()
                {
                    return (StreamCipher)CFBBlockCipher.newInstance(AESEngine.newInstance(), 128);
                }
            },
            new Source("CFB8/AES", 16, 16)
            {
                StreamCipher create()
                {
                    return (StreamCipher)CFBBlockCipher.newInstance(AESEngine.newInstance(), 8);
                }
            },
            new Source("OFB128/AES", 16, 16)
            {
                StreamCipher create()
                {
                    return new OFBBlockCipher(AESEngine.newInstance(), 128);
                }
            },
            new Source("OFB8/AES", 16, 16)
            {
                StreamCipher create()
                {
                    return new OFBBlockCipher(AESEngine.newInstance(), 8);
                }
            },
            new Source("GOFB/GOST28147", 32, 8)
            {
                StreamCipher create()
                {
                    return new GOFBBlockCipher(new GOST28147Engine());
                }
            },
            new Source("GCFB/GOST28147", 32, 8)
            {
                StreamCipher create()
                {
                    return new GCFBBlockCipher(new GOST28147Engine());
                }
            },
            new Source("KCTR/DSTU7624", 16, 16)
            {
                StreamCipher create()
                {
                    return new KCTRBlockCipher(new DSTU7624Engine(128));
                }
            },
            new Source("G3413CTR/GOST3412-2015", 32, 8)
            {
                StreamCipher create()
                {
                    return new G3413CTRBlockCipher(new GOST3412_2015Engine());
                }
            },
            new Source("G3413CFB/GOST3412-2015", 32, 16)
            {
                StreamCipher create()
                {
                    return new G3413CFBBlockCipher(new GOST3412_2015Engine());
                }
            },
            new Source("G3413OFB/GOST3412-2015", 32, 16)
            {
                StreamCipher create()
                {
                    return new G3413OFBBlockCipher(new GOST3412_2015Engine());
                }
            },
            new Source("Salsa20", 32, 8)
            {
                StreamCipher create()
                {
                    return new Salsa20Engine();
                }
            },
            new Source("XSalsa20", 32, 24)
            {
                StreamCipher create()
                {
                    return new XSalsa20Engine();
                }
            },
            new Source("ChaCha", 32, 8)
            {
                StreamCipher create()
                {
                    return new ChaChaEngine();
                }
            },
            new Source("ChaCha7539", 32, 12)
            {
                StreamCipher create()
                {
                    return new ChaCha7539Engine();
                }
            },
            new Source("XChaCha20", 32, 24)
            {
                StreamCipher create()
                {
                    return new XChaCha20Engine();
                }
            },
            new Source("RC4", 16, 0)
            {
                StreamCipher create()
                {
                    return new RC4Engine();
                }
            },
            new Source("HC128", 16, 16)
            {
                StreamCipher create()
                {
                    return new HC128Engine();
                }
            },
            new Source("HC256", 32, 32)
            {
                StreamCipher create()
                {
                    return new HC256Engine();
                }
            },
            new Source("ISAAC", 16, 0)
            {
                StreamCipher create()
                {
                    return new ISAACEngine();
                }
            },
            new Source("VMPC", 16, 16)
            {
                StreamCipher create()
                {
                    return new VMPCEngine();
                }
            },
            new Source("VMPC-KSA3", 16, 16)
            {
                StreamCipher create()
                {
                    return new VMPCKSA3Engine();
                }
            },
            new Source("Grainv1", 10, 8)
            {
                StreamCipher create()
                {
                    return new Grainv1Engine();
                }
            },
            new Source("Grain128", 16, 12)
            {
                StreamCipher create()
                {
                    return new Grain128Engine();
                }
            },
            new Source("Zuc128", 16, 16)
            {
                StreamCipher create()
                {
                    return new Zuc128Engine();
                }
            },
            new Source("Zuc256", 32, 25)
            {
                StreamCipher create()
                {
                    return new Zuc256Engine();
                }
            }
        };
    }

    public String getName()
    {
        return "StreamCipherOverlap";
    }

    public void performTest()
        throws Exception
    {
        Source[] sources = sources();
        byte[] message = fill(LEN, 31);

        for (int i = 0; i != sources.length; i++)
        {
            Source source = sources[i];

            byte[] cipherText = process(source, true, message);

            isTrue(source.name + " did not encrypt", !areEqual(message, cipherText));
            isTrue(source.name + " did not round trip", areEqual(message, process(source, false, cipherText)));

            checkOverlap(source, true, message, cipherText);
            checkOverlap(source, false, cipherText, message);
        }
    }

    private byte[] process(Source source, boolean forEncryption, byte[] input)
    {
        StreamCipher cipher = source.create();
        byte[] output = new byte[input.length];

        cipher.init(forEncryption, source.params);
        isEquals(source.name + " length", input.length, cipher.processBytes(input, 0, input.length, output, 0));

        return output;
    }

    private void checkOverlap(Source source, boolean forEncryption, byte[] input, byte[] expected)
    {
        for (int i = 0; i != OUT_OFFS.length; i++)
        {
            int outOff = OUT_OFFS[i];
            String label = source.name + (forEncryption ? " encrypt" : " decrypt") + ", output at " + outOff;

            // one call
            byte[] buffer = new byte[IN_OFF + LEN + outOff + 8];
            System.arraycopy(input, 0, buffer, IN_OFF, LEN);

            StreamCipher cipher = source.create();
            cipher.init(forEncryption, source.params);
            isEquals(label + ": length", LEN, cipher.processBytes(buffer, IN_OFF, LEN, buffer, outOff));
            checkOutput(label, expected, buffer, outOff);

            // the same in two calls, the second starting part way through a block
            buffer = new byte[IN_OFF + LEN + outOff + 8];
            System.arraycopy(input, 0, buffer, IN_OFF, LEN);

            cipher = source.create();
            cipher.init(forEncryption, source.params);

            int first = 37;
            byte[] head = new byte[first];
            cipher.processBytes(buffer, IN_OFF, first, head, 0);
            cipher.processBytes(buffer, IN_OFF + first, LEN - first, buffer, outOff + first);
            System.arraycopy(head, 0, buffer, outOff, first);
            checkOutput(label + ", in two calls", expected, buffer, outOff);
        }
    }

    private void checkOutput(String label, byte[] expected, byte[] buffer, int outOff)
    {
        for (int i = 0; i != expected.length; i++)
        {
            if (expected[i] != buffer[outOff + i])
            {
                fail(label + ": output differs at " + i);
            }
        }
    }

    public static void main(String[] args)
    {
        runTest(new StreamCipherOverlapTest());
    }
}
