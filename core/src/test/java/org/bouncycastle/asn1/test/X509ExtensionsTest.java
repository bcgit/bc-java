package org.bouncycastle.asn1.test;

import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509ExtensionsGenerator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.test.SimpleTest;

public class X509ExtensionsTest
    extends SimpleTest
{
    private static final ASN1ObjectIdentifier OID_2 = new ASN1ObjectIdentifier("1.2.2");
    private static final ASN1ObjectIdentifier OID_3 = new ASN1ObjectIdentifier("1.2.3");
    private static final ASN1ObjectIdentifier OID_1 = new ASN1ObjectIdentifier("1.2.1");

    public String getName()
    {
        return "X509Extensions";
    }

    public void performTest() throws Exception
    {
        X509ExtensionsGenerator gen = new X509ExtensionsGenerator();

        gen.addExtension(OID_1, true, new byte[20]);
        gen.addExtension(OID_2, true, new byte[20]);

        X509Extensions ext1 = gen.generate();
        X509Extensions ext2 = gen.generate();

        if (!ext1.equals(ext2))
        {
            fail("equals test failed");
        }

        gen.reset();

        gen.addExtension(OID_2, true, new byte[20]);
        gen.addExtension(OID_1, true, new byte[20]);

        ext2 = gen.generate();

        if (ext1.equals(ext2))
        {
            fail("inequality test failed");
        }

        if (!ext1.equivalent(ext2))
        {
            fail("equivalence true failed");
        }

        gen.reset();

        gen.addExtension(OID_1, true, new byte[22]);
        gen.addExtension(OID_2, true, new byte[20]);

        ext2 = gen.generate();

        if (ext1.equals(ext2))
        {
            fail("inequality 1 failed");
        }

        if (ext1.equivalent(ext2))
        {
            fail("non-equivalence 1 failed");
        }

        gen.reset();

        gen.addExtension(OID_3, true, new byte[20]);
        gen.addExtension(OID_2, true, new byte[20]);

        ext2 = gen.generate();

        if (ext1.equals(ext2))
        {
            fail("inequality 2 failed");
        }

        if (ext1.equivalent(ext2))
        {
            fail("non-equivalence 2 failed");
        }

        try
        {
            gen.addExtension(OID_2, true, new byte[20]);
            fail("repeated oid");
        }
        catch (IllegalArgumentException e)
        {
            if (!e.getMessage().equals("extension 1.2.2 already added"))
            {
                fail("wrong exception on repeated oid: " + e.getMessage());
            }
        }

        collidingOidTest();
    }

    /**
     * The OID tables behind Extensions, X509Extensions and ExtendedKeyUsage are built from the input
     * before anything is verified, so a block of OIDs sharing one hash code must still index in linear time.
     */
    private void collidingOidTest()
        throws Exception
    {
        ASN1ObjectIdentifier[] oids = collidingOIDs(15);
        int n = oids.length;
        for (int i = 1; i != n; i++)
        {
            isTrue("hash codes should coincide", oids[0].hashCode() == oids[i].hashCode());
        }

        ASN1EncodableVector exts = new ASN1EncodableVector(n);
        for (int i = 0; i != n; i++)
        {
            exts.add(new DERSequence(new ASN1Encodable[]{ oids[i], new DEROctetString(new byte[]{ 0x05, 0x00 }) }));
        }
        ASN1Sequence extSeq = ASN1Sequence.getInstance(new DERSequence(exts).getEncoded());
        ASN1Sequence ekuSeq = ASN1Sequence.getInstance(new DERSequence(oids).getEncoded());

        long start = System.currentTimeMillis();
        Extensions extensions = Extensions.getInstance(extSeq);
        X509Extensions legacy = X509Extensions.getInstance(extSeq);
        ExtendedKeyUsage eku = ExtendedKeyUsage.getInstance(ekuSeq);
        long elapsed = System.currentTimeMillis() - start;

        isTrue("extension count", extensions.getExtensionOIDs().length == n);
        isTrue("last extension lookup", extensions.getExtension(oids[n - 1]) != null);
        isTrue("absent extension lookup", extensions.getExtension(OID_1) == null);
        isTrue("legacy last extension lookup", legacy.getExtension(oids[n - 1]) != null);
        isTrue("legacy extension count", legacy.getExtensionOIDs().length == n);
        isTrue("key purpose count", eku.size() == n);
        isTrue("last key purpose lookup", eku.hasKeyPurposeId(KeyPurposeId.getInstance(oids[n - 1])));
        isTrue("absent key purpose lookup", !eku.hasKeyPurposeId(KeyPurposeId.getInstance(OID_1)));
        isTrue("colliding OIDs took " + elapsed + "ms", elapsed < 3000L);
    }

    /**
     * 2^log2n distinct OIDs under 1.3 whose ASN1ObjectIdentifier.hashCode() values coincide. The hash is
     * a 257-multiplier fold over the content octets from the last to the first, so starting from a common
     * tail each five-octet component position allows a birthday search for two encodings that leave the
     * fold in the same state, after which every choice at every position gives the same hash.
     */
    private static ASN1ObjectIdentifier[] collidingOIDs(int log2n)
    {
        byte[] tail = { 0x06, 0x01, 0x04, 0x01, 0x7F };
        int length = 1 + 5 * log2n + tail.length;
        int state = foldHash(length + 1, tail);
        byte[][][] pairs = new byte[log2n][][];
        Random rnd = new Random(1);

        for (int i = 0; i < log2n; i++)
        {
            pairs[i] = collidingPair(state, rnd);
            state = foldHash(state, pairs[i][0]);
        }

        ASN1ObjectIdentifier[] oids = new ASN1ObjectIdentifier[1 << log2n];
        for (int x = 0; x < oids.length; x++)
        {
            byte[] enc = new byte[2 + length];
            enc[0] = 0x06;
            enc[1] = (byte)length;
            enc[2] = 0x2B;
            int p = 3;
            for (int i = log2n - 1; i >= 0; i--)
            {
                System.arraycopy(pairs[i][(x >> i) & 1], 0, enc, p, 5);
                p += 5;
            }
            System.arraycopy(tail, 0, enc, p, tail.length);
            oids[x] = ASN1ObjectIdentifier.getInstance(enc);
        }

        return oids;
    }

    private static int foldHash(int state, byte[] block)
    {
        for (int i = block.length - 1; i >= 0; i--)
        {
            state *= 257;
            state ^= block[i];
        }
        return state;
    }

    private static byte[][] collidingPair(int state, Random rnd)
    {
        Map seen = new HashMap();
        for (;;)
        {
            byte[] b = { (byte)(0x80 | (1 + rnd.nextInt(127))), (byte)(0x80 | rnd.nextInt(128)),
                (byte)(0x80 | rnd.nextInt(128)), (byte)(0x80 | rnd.nextInt(128)), (byte)rnd.nextInt(128) };
            Integer out = Integers.valueOf(foldHash(state, b));
            byte[] prev = (byte[])seen.get(out);
            if (prev != null && !Arrays.areEqual(prev, b))
            {
                return new byte[][]{ prev, b };
            }
            seen.put(out, b);
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new X509ExtensionsTest());
    }
}
