package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyEncoder;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.EthereumIESEngine;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.EphemeralKeyPairGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.IESParameters;
import org.bouncycastle.crypto.params.IESWithCipherParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.parsers.ECIESPublicKeyParser;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * test for Ethereum flavor of ECIES - Elliptic Curve Integrated Encryption Scheme
 * <p>
 * Note the IV is always required when passing parameters, as the IV is added to the MAC.
 */
public class EthereumIESTest
    extends SimpleTest
{
    private static byte[] TWOFISH_IV = Hex.decode("000102030405060708090a0b0c0d0e0f");

    EthereumIESTest()
    {
    }

    public String getName()
    {
        return "EthereumIES";
    }

    private void doStaticTest(byte[] iv)
        throws Exception
    {
        BigInteger n = new BigInteger("6277101735386680763835789423176059013767194773182842284081");

        ECCurve.Fp curve = new ECCurve.Fp(
            new BigInteger("6277101735386680763835789423207666416083908700390324961279"), // q
            new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16), // a
            new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16), // b
            n, ECConstants.ONE);

        ECDomainParameters params = new ECDomainParameters(
            curve,
            curve.decodePoint(Hex.decode("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012")), // G
            n);

        ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
            new BigInteger("651056770906015076056810763456358567190100156695615665659"), // d
            params);

        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
            curve.decodePoint(Hex.decode("0262b12d60690cdcf330babab6e69763b471f994dd702d16a5")), // Q
            params);

        AsymmetricCipherKeyPair p1 = new AsymmetricCipherKeyPair(pubKey, priKey);
        AsymmetricCipherKeyPair p2 = new AsymmetricCipherKeyPair(pubKey, priKey);

        byte[] commonMac = Hex.decode("0262b12d60690cdcf330baba03188da80eb03090f67cbf2043a18800f4ff0a0262b12d60690cdcf330bab6e69763b471f994dd2d16a5fd82ff1012b6e69763b4");

        //
        // stream test
        //
        EthereumIESEngine i1 = new EthereumIESEngine(
            new ECDHBasicAgreement(),
            new EthereumIESEngine.HandshakeKDFFunction(1, new SHA1Digest()),
            new HMac(new SHA1Digest()),
            commonMac);
        EthereumIESEngine i2 = new EthereumIESEngine(
            new ECDHBasicAgreement(),
            new EthereumIESEngine.HandshakeKDFFunction(1, new SHA1Digest()),
            new HMac(new SHA1Digest()),
            commonMac);
        byte[] d = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        byte[] e = new byte[]{8, 7, 6, 5, 4, 3, 2, 1};
        CipherParameters p = new ParametersWithIV(new IESParameters(d, e, 64), new byte[32]);

        i1.init(true, p1.getPrivate(), p2.getPublic(), p);
        i2.init(false, p2.getPrivate(), p1.getPublic(), p);

        byte[] message = Hex.decode("1234567890abcdef");

        byte[] out1 = i1.processBlock(message, 0, message.length);

        if (!areEqual(out1, Hex.decode("1cf75e9e93f8812e7f3da0ad3491b9690431f2b65260af65e9d7df17")))
        {
            fail("stream cipher test failed on enc");
        }

        byte[] out2 = i2.processBlock(out1, 0, out1.length);

        if (!areEqual(out2, message))
        {
            fail("stream cipher test failed");
        }

        //
        // twofish with CBC
        //
        BufferedBlockCipher c1 = new PaddedBufferedBlockCipher(
            new CBCBlockCipher(new TwofishEngine()));
        BufferedBlockCipher c2 = new PaddedBufferedBlockCipher(
            new CBCBlockCipher(new TwofishEngine()));
        i1 = new EthereumIESEngine(
            new ECDHBasicAgreement(),
            new EthereumIESEngine.HandshakeKDFFunction(1, new SHA1Digest()),
            new HMac(new SHA1Digest()),
            commonMac,
            c1);
        i2 = new EthereumIESEngine(
            new ECDHBasicAgreement(),
            new EthereumIESEngine.HandshakeKDFFunction(1, new SHA1Digest()),
            new HMac(new SHA1Digest()),
            commonMac,
            c2);
        d = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        e = new byte[]{8, 7, 6, 5, 4, 3, 2, 1};
        p = new IESWithCipherParameters(d, e, 64, 128);

        if (iv != null)
        {
            p = new ParametersWithIV(p, iv);
        }

        i1.init(true, p1.getPrivate(), p2.getPublic(), p);
        i2.init(false, p2.getPrivate(), p1.getPublic(), p);

        message = Hex.decode("1234567890abcdef");

        out1 = i1.processBlock(message, 0, message.length);

        if (!areEqual(out1, (iv == null) ?
            Hex.decode("b8a06ea5c2b9df28b58a0a90a734cde8c9c02903e5c220021fe4417410d1e53a32a71696")
            : Hex.decode("34bb9676b087d0b3a016e70a93c4afcb507882a53c5ca7a770913e654ff1422c4b236cbf")))
        {
            fail("twofish cipher test failed on enc");
        }

        out2 = i2.processBlock(out1, 0, out1.length);

        if (!areEqual(out2, message))
        {
            fail("twofish cipher test failed");
        }
    }

    private void doShortTest(byte[] iv)
        throws Exception
    {
        BigInteger n = new BigInteger("6277101735386680763835789423176059013767194773182842284081");

        ECCurve.Fp curve = new ECCurve.Fp(
            new BigInteger("6277101735386680763835789423207666416083908700390324961279"), // q
            new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16), // a
            new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16), // b
            n, ECConstants.ONE);

        ECDomainParameters params = new ECDomainParameters(
            curve,
            curve.decodePoint(Hex.decode("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012")), // G
            n);

        ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
            new BigInteger("651056770906015076056810763456358567190100156695615665659"), // d
            params);

        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
            curve.decodePoint(Hex.decode("0262b12d60690cdcf330babab6e69763b471f994dd702d16a5")), // Q
            params);

        AsymmetricCipherKeyPair p1 = new AsymmetricCipherKeyPair(pubKey, priKey);
        AsymmetricCipherKeyPair p2 = new AsymmetricCipherKeyPair(pubKey, priKey);

        byte[] commonMac = Hex.decode("0262b12d60690cdcf330baba03188da80eb03090f67cbf2043a18800f4ff0a0262b12d60690cdcf330bab6e69763b471f994dd2d16a5fd82ff1012b6e69763b4");

        //
        // stream test - V 0
        //
        EthereumIESEngine i1 = new EthereumIESEngine(
            new ECDHBasicAgreement(),
            new EthereumIESEngine.HandshakeKDFFunction(1, new SHA1Digest()),
            new HMac(new SHA1Digest()),
            commonMac);
        EthereumIESEngine i2 = new EthereumIESEngine(
            new ECDHBasicAgreement(),
            new EthereumIESEngine.HandshakeKDFFunction(1, new SHA1Digest()),
            new HMac(new SHA1Digest()),
            commonMac);
        byte[] d = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        byte[] e = new byte[]{8, 7, 6, 5, 4, 3, 2, 1};
        CipherParameters p = new ParametersWithIV(new IESParameters(d, e, 64), new byte[32]);

        i1.init(true, p1.getPrivate(), p2.getPublic(), p);
        i2.init(false, p2.getPrivate(), p1.getPublic(), p);

        byte[] message = new byte[0];

        byte[] out1 = i1.processBlock(message, 0, message.length);

        byte[] out2 = i2.processBlock(out1, 0, out1.length);

        if (!areEqual(out2, message))
        {
            fail("stream cipher test failed");
        }

        try
        {
            i2.processBlock(out1, 0, out1.length - 1);
            fail("no exception");
        }
        catch (InvalidCipherTextException ex)
        {
            if (!"length of input must be greater than the MAC and V combined".equals(ex.getMessage()))
            {
                fail("wrong exception");
            }
        }

        // with ephemeral key pair

        // Generate the ephemeral key pair
        ECKeyPairGenerator gen = new ECKeyPairGenerator();
        gen.init(new ECKeyGenerationParameters(params, new SecureRandom()));

        EphemeralKeyPairGenerator ephKeyGen = new EphemeralKeyPairGenerator(gen, new KeyEncoder()
        {
            public byte[] getEncoded(AsymmetricKeyParameter keyParameter)
            {
                return ((ECPublicKeyParameters)keyParameter).getQ().getEncoded(false);
            }
        });

        i1.init(p2.getPublic(), p, ephKeyGen);
        i2.init(p2.getPrivate(), p, new ECIESPublicKeyParser(params));

        out1 = i1.processBlock(message, 0, message.length);

        out2 = i2.processBlock(out1, 0, out1.length);

        if (!areEqual(out2, message))
        {
            fail("V cipher test failed");
        }

        try
        {
            i2.processBlock(out1, 0, out1.length - 1);
            fail("no exception");
        }
        catch (InvalidCipherTextException ex)
        {
            if (!"length of input must be greater than the MAC and V combined".equals(ex.getMessage()))
            {
                fail("wrong exception");
            }
        }
    }

    private void doEphemeralTest(byte[] iv, final boolean usePointCompression)
        throws Exception
    {
        BigInteger n = new BigInteger("6277101735386680763835789423176059013767194773182842284081");

        ECCurve.Fp curve = new ECCurve.Fp(
            new BigInteger("6277101735386680763835789423207666416083908700390324961279"), // q
            new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16), // a
            new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16), // b
            n, ECConstants.ONE);

        ECDomainParameters params = new ECDomainParameters(
            curve,
            curve.decodePoint(Hex.decode("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012")), // G
            n);

        ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
            new BigInteger("651056770906015076056810763456358567190100156695615665659"), // d
            params);

        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
            curve.decodePoint(Hex.decode("0262b12d60690cdcf330babab6e69763b471f994dd702d16a5")), // Q
            params);

        AsymmetricCipherKeyPair p1 = new AsymmetricCipherKeyPair(pubKey, priKey);
        AsymmetricCipherKeyPair p2 = new AsymmetricCipherKeyPair(pubKey, priKey);

        // Generate the ephemeral key pair
        ECKeyPairGenerator gen = new ECKeyPairGenerator();
        gen.init(new ECKeyGenerationParameters(params, new SecureRandom()));

        EphemeralKeyPairGenerator ephKeyGen = new EphemeralKeyPairGenerator(gen, new KeyEncoder()
        {
            public byte[] getEncoded(AsymmetricKeyParameter keyParameter)
            {
                return ((ECPublicKeyParameters)keyParameter).getQ().getEncoded(usePointCompression);
            }
        });

        byte[] commonMac = Hex.decode("0262b12d60690cdcf330baba03188da80eb03090f67cbf2043a18800f4ff0a0262b12d60690cdcf330bab6e69763b471f994dd2d16a5fd82ff1012b6e69763b4");

        //
        // stream test
        //
        EthereumIESEngine i1 = new EthereumIESEngine(
            new ECDHBasicAgreement(),
            new EthereumIESEngine.HandshakeKDFFunction(1, new SHA1Digest()),
            new HMac(new SHA1Digest()),
            commonMac);
        EthereumIESEngine i2 = new EthereumIESEngine(
            new ECDHBasicAgreement(),
            new EthereumIESEngine.HandshakeKDFFunction(1, new SHA1Digest()),
            new HMac(new SHA1Digest()),
            commonMac);

        byte[] d = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        byte[] e = new byte[]{8, 7, 6, 5, 4, 3, 2, 1};
        CipherParameters p = new ParametersWithIV(new IESParameters(d, e, 64), new byte[32]);

        i1.init(p2.getPublic(), p, ephKeyGen);
        i2.init(p2.getPrivate(), p, new ECIESPublicKeyParser(params));

        byte[] message = Hex.decode("1234567890abcdef");

        byte[] out1 = i1.processBlock(message, 0, message.length);

        byte[] out2 = i2.processBlock(out1, 0, out1.length);

        if (!areEqual(out2, message))
        {
            fail("stream cipher test failed");
        }

        //
        // twofish with CBC
        //
        BufferedBlockCipher c1 = new PaddedBufferedBlockCipher(
            new CBCBlockCipher(new TwofishEngine()));
        BufferedBlockCipher c2 = new PaddedBufferedBlockCipher(
            new CBCBlockCipher(new TwofishEngine()));
        i1 = new EthereumIESEngine(
            new ECDHBasicAgreement(),
            new EthereumIESEngine.HandshakeKDFFunction(1, new SHA1Digest()),
            new HMac(new SHA1Digest()),
            commonMac,
            c1);
        i2 = new EthereumIESEngine(
            new ECDHBasicAgreement(),
            new EthereumIESEngine.HandshakeKDFFunction(1, new SHA1Digest()),
            new HMac(new SHA1Digest()),
            commonMac,
            c2);
        d = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        e = new byte[]{8, 7, 6, 5, 4, 3, 2, 1};
        p = new IESWithCipherParameters(d, e, 64, 128);

        if (iv != null)
        {
            p = new ParametersWithIV(p, iv);
        }

        i1.init(p2.getPublic(), p, ephKeyGen);
        i2.init(p2.getPrivate(), p, new ECIESPublicKeyParser(params));

        message = Hex.decode("1234567890abcdef");

        out1 = i1.processBlock(message, 0, message.length);

        out2 = i2.processBlock(out1, 0, out1.length);

        if (!areEqual(out2, message))
        {
            fail("twofish cipher test failed");
        }
    }

    private void doTest(AsymmetricCipherKeyPair p1, AsymmetricCipherKeyPair p2)
        throws Exception
    {
        byte[] commonMac = Hex.decode("0262b12d60690cdcf330baba03188da80eb03090f67cbf2043a18800f4ff0a0262b12d60690cdcf330bab6e69763b471f994dd2d16a5fd82ff1012b6e69763b4");

        //
        // stream test
        //
        EthereumIESEngine i1 = new EthereumIESEngine(
            new ECDHBasicAgreement(),
            new EthereumIESEngine.HandshakeKDFFunction(1, new SHA1Digest()),
            new HMac(new SHA1Digest()),
            commonMac);
        EthereumIESEngine i2 = new EthereumIESEngine(
            new ECDHBasicAgreement(),
            new EthereumIESEngine.HandshakeKDFFunction(1, new SHA1Digest()),
            new HMac(new SHA1Digest()),
            commonMac);
        byte[] d = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        byte[] e = new byte[]{8, 7, 6, 5, 4, 3, 2, 1};
        ParametersWithIV p = new ParametersWithIV(new IESParameters(d, e, 64), new byte[32]);

        i1.init(true, p1.getPrivate(), p2.getPublic(), p);
        i2.init(false, p2.getPrivate(), p1.getPublic(), p);

        byte[] message = Hex.decode("1234567890abcdef");

        byte[] out1 = i1.processBlock(message, 0, message.length);

        byte[] out2 = i2.processBlock(out1, 0, out1.length);

        if (!areEqual(out2, message))
        {
            fail("stream cipher test failed");
        }

        //
        // twofish with CBC
        //
        BufferedBlockCipher c1 = new PaddedBufferedBlockCipher(
            new CBCBlockCipher(new TwofishEngine()));
        BufferedBlockCipher c2 = new PaddedBufferedBlockCipher(
            new CBCBlockCipher(new TwofishEngine()));
        i1 = new EthereumIESEngine(
            new ECDHBasicAgreement(),
            new EthereumIESEngine.HandshakeKDFFunction(1, new SHA1Digest()),
            new HMac(new SHA1Digest()),
            commonMac,
            c1);
        i2 = new EthereumIESEngine(
            new ECDHBasicAgreement(),
            new EthereumIESEngine.HandshakeKDFFunction(1, new SHA1Digest()),
            new HMac(new SHA1Digest()),
            commonMac,
            c2);
        d = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        e = new byte[]{8, 7, 6, 5, 4, 3, 2, 1};
        p = new ParametersWithIV(new IESWithCipherParameters(d, e, 64, 128), new byte[16]);

        i1.init(true, p1.getPrivate(), p2.getPublic(), p);
        i2.init(false, p2.getPrivate(), p1.getPublic(), p);

        message = Hex.decode("1234567890abcdef");

        out1 = i1.processBlock(message, 0, message.length);

        out2 = i2.processBlock(out1, 0, out1.length);

        if (!areEqual(out2, message))
        {
            fail("twofish cipher test failed");
        }
    }

    // Regression for the static-key stream-mode MAC-key layout (the EthereumIESEngine sibling of the
    // IESEngine fix): in static-static stream mode the MAC key must not be recoverable from the
    // keystream. The legacy layout placed the keystream K1 before the MAC key K2, so a single
    // known-plaintext leak of K1 (= M ^ C) also exposed the MAC key of any shorter message - letting
    // an attacker forge a valid ciphertext+tag from one observation. With K2 now taken from a fixed
    // prefix of the KDF output, that slice of the leaked keystream is no longer the MAC key, so the
    // constructed forgery must be rejected. The Ethereum variant keys the HMAC with SHA-256(K2) and
    // also absorbs the IV and commonMac - all public, so the forgery just replays them verbatim.
    private void doForgeryTest()
        throws Exception
    {
        BigInteger n = new BigInteger("6277101735386680763835789423176059013767194773182842284081");

        ECCurve.Fp curve = new ECCurve.Fp(
            new BigInteger("6277101735386680763835789423207666416083908700390324961279"), // q
            new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16), // a
            new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16), // b
            n, ECConstants.ONE);

        ECDomainParameters params = new ECDomainParameters(curve,
            curve.decodePoint(Hex.decode("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012")), n);

        ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
            new BigInteger("651056770906015076056810763456358567190100156695615665659"), params);
        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
            curve.decodePoint(Hex.decode("0262b12d60690cdcf330babab6e69763b471f994dd702d16a5")), params);

        AsymmetricCipherKeyPair p1 = new AsymmetricCipherKeyPair(pubKey, priKey);
        AsymmetricCipherKeyPair p2 = new AsymmetricCipherKeyPair(pubKey, priKey);

        byte[] commonMac = Hex.decode("0262b12d60690cdcf330baba03188da80eb03090f67cbf2043a18800f4ff0a0262b12d60690cdcf330bab6e69763b471f994dd2d16a5fd82ff1012b6e69763b4");
        byte[] iv = new byte[32];

        int macKeyBytes = 8; // 64-bit MAC key
        // no encoding vector, so the MAC is taken over (IV || ciphertext || commonMac) - keeps the forgery construction simple
        CipherParameters param = new ParametersWithIV(new IESParameters(new byte[]{ 1, 2, 3, 4, 5, 6, 7, 8 }, null, macKeyBytes * 8), iv);

        // 1. attacker observes one known-plaintext ciphertext of length L (>= macKeyBytes)
        byte[] knownPt = Hex.decode("000102030405060708090a0b0c0d0e0f10111213"); // L = 20
        EthereumIESEngine enc = new EthereumIESEngine(new ECDHBasicAgreement(),
            new EthereumIESEngine.HandshakeKDFFunction(1, new SHA1Digest()), new HMac(new SHA1Digest()), commonMac);
        enc.init(true, p1.getPrivate(), p2.getPublic(), param);
        byte[] out = enc.processBlock(knownPt, 0, knownPt.length); // V absent in static-static mode: out = C || T

        byte[] leaked = new byte[knownPt.length]; // recovered keystream = M ^ C over the L plaintext bytes
        for (int i = 0; i != leaked.length; i++)
        {
            leaked[i] = (byte)(knownPt[i] ^ out[i]);
        }

        // 2. forge a shorter message, assuming the legacy keystream-then-MAC-key layout
        int forgeLen = knownPt.length - macKeyBytes; // L'
        byte[] forgedPt = Hex.decode("ffffffffffffffffffffffff"); // 12 bytes (= L')
        byte[] forgedC = new byte[forgeLen];
        for (int i = 0; i != forgeLen; i++)
        {
            forgedC[i] = (byte)(forgedPt[i] ^ leaked[i]); // K1' = leaked[0..L']
        }

        // K2' = leaked[L'..L'+macKeyBytes]; the Ethereum variant keys the HMAC with SHA-256(K2)
        byte[] K2 = Arrays.copyOfRange(leaked, forgeLen, forgeLen + macKeyBytes);
        Digest hash = SHA256Digest.newInstance();
        byte[] K2hash = new byte[hash.getDigestSize()];
        hash.update(K2, 0, K2.length);
        hash.doFinal(K2hash, 0);

        HMac hmac = new HMac(new SHA1Digest());
        hmac.init(new KeyParameter(K2hash));
        hmac.update(iv, 0, iv.length);               // IV is absorbed first (Ethereum change)
        hmac.update(forgedC, 0, forgedC.length);
        hmac.update(commonMac, 0, commonMac.length); // commonMac is appended (Ethereum change)
        byte[] forgedTag = new byte[hmac.getMacSize()];
        hmac.doFinal(forgedTag, 0);

        byte[] forged = Arrays.concatenate(forgedC, forgedTag);

        // 3. the recipient must reject the forgery
        EthereumIESEngine dec = new EthereumIESEngine(new ECDHBasicAgreement(),
            new EthereumIESEngine.HandshakeKDFFunction(1, new SHA1Digest()), new HMac(new SHA1Digest()), commonMac);
        dec.init(false, p2.getPrivate(), p1.getPublic(), param);
        try
        {
            dec.processBlock(forged, 0, forged.length);
            fail("static-key stream EthereumIES accepted a cross-message MAC forgery");
        }
        catch (InvalidCipherTextException expected)
        {
            // expected: K2 is a fixed prefix of the KDF output, not a recoverable slice of the keystream
        }
    }

    public void performTest()
        throws Exception
    {
        doForgeryTest();
        doStaticTest(TWOFISH_IV);
        doShortTest(null);

        BigInteger n = new BigInteger("6277101735386680763835789423176059013767194773182842284081");

        ECCurve.Fp curve = new ECCurve.Fp(
            new BigInteger("6277101735386680763835789423207666416083908700390324961279"), // q
            new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16), // a
            new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16), // b
            n, ECConstants.ONE);

        ECDomainParameters params = new ECDomainParameters(
            curve,
            curve.decodePoint(Hex.decode("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012")), // G
            n);

        ECKeyPairGenerator eGen = new ECKeyPairGenerator();
        KeyGenerationParameters gParam = new ECKeyGenerationParameters(params, new SecureRandom());

        eGen.init(gParam);

        AsymmetricCipherKeyPair p1 = eGen.generateKeyPair();
        AsymmetricCipherKeyPair p2 = eGen.generateKeyPair();

        doTest(p1, p2);

        doEphemeralTest(TWOFISH_IV, false);
        doEphemeralTest(TWOFISH_IV, true);
    }

    public static void main(
        String[] args)
    {
        runTest(new EthereumIESTest());
    }
}
