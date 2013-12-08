package org.bouncycastle.crypto.test;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.crypto.agreement.kdf.DHKDFParameters;
import org.bouncycastle.crypto.agreement.kdf.ECDHKEKGenerator;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * ECDHKEK Generator tests.
 */
public class ECDHKEKGeneratorTest
    extends SimpleTest
{
    private byte[] seed1 = Hex.decode("db4a8daba1f98791d54e940175dd1a5f3a0826a1066aa9b668d4dc1e1e0790158dcad1533c03b44214d1b61fefa8b579");
    private ASN1ObjectIdentifier alg1 = NISTObjectIdentifiers.id_aes256_wrap;
    private byte[] result1 = Hex.decode("8ecc6d85caf25eaba823a7d620d4ab0d33e4c645f2");

    private byte[] seed2 = Hex.decode("75d7487b5d3d2bfb3c69ce0365fe64e3bfab5d0d63731628a9f47eb8fddfa28c65decaf228a0b38f0c51c6a3356d7c56");
    private ASN1ObjectIdentifier alg2 = NISTObjectIdentifiers.id_aes128_wrap;
    private byte[] result2 = Hex.decode("042be1faca3a4a8fc859241bfb87ba35");

    private byte[] seed3 = Hex.decode("fdeb6d809f997e8ac174d638734dc36d37aaf7e876e39967cd82b1cada3de772449788461ee7f856bad9305627f8e48b");
    private ASN1ObjectIdentifier alg3 = PKCSObjectIdentifiers.id_alg_CMS3DESwrap;
    private byte[] result3 = Hex.decode("bcd701fc92109b1b9d6f3b6497ad5ca9627fa8a597010305");

    public ECDHKEKGeneratorTest()
    {
    }

    public void performTest()
    {
        checkMask(1, new ECDHKEKGenerator(new SHA1Digest()), new DHKDFParameters(alg1, 256, seed1), result1);
        checkMask(2, new ECDHKEKGenerator(new SHA1Digest()), new DHKDFParameters(alg2, 128, seed2), result2);
        checkMask(3, new ECDHKEKGenerator(new SHA1Digest()), new DHKDFParameters(alg3, 192, seed3), result3);
    }

    private void checkMask(
        int                count,
        DerivationFunction kdf,
        DerivationParameters params,
        byte[]             result)
    {
        byte[]             data = new byte[result.length];

        kdf.init(params);

        kdf.generateBytes(data, 0, data.length);

        if (!areEqual(result, data))
        {
            fail("ECDHKEKGenerator failed generator test " + count);
        }
    }

    public String getName()
    {
        return "ECDHKEKGenerator";
    }

    public static void main(
        String[]    args)
    {
        runTest(new ECDHKEKGeneratorTest());
    }
}
