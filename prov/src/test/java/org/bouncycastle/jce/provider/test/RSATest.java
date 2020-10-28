package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashSet;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.jcajce.spec.OpenSSHPrivateKeySpec;
import org.bouncycastle.jcajce.spec.OpenSSHPublicKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class RSATest
    extends SimpleTest
{
    /**
     * a fake random number generator - we just want to make sure the random numbers
     * aren't random so that we get the same output, while still getting to test the
     * key generation facilities.
     */
    private class FixedSecureRandom
        extends SecureRandom
    {
        byte[]  seed = {
                (byte)0xaa, (byte)0xfd, (byte)0x12, (byte)0xf6, (byte)0x59,
                (byte)0xca, (byte)0xe6, (byte)0x34, (byte)0x89, (byte)0xb4,
                (byte)0x79, (byte)0xe5, (byte)0x07, (byte)0x6d, (byte)0xde,
                (byte)0xc2, (byte)0xf0, (byte)0x6c, (byte)0xb5, (byte)0x8f
        };

        public void nextBytes(
            byte[]  bytes)
        {
            int offset = 0;

            while ((offset + seed.length) < bytes.length)
            {
                System.arraycopy(seed, 0, bytes, offset, seed.length);
                offset += seed.length;
            }

            System.arraycopy(seed, 0, bytes, offset, bytes.length - offset);
        }
    }

    private RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(
        new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
        new BigInteger("11", 16));

    private RSAPrivateCrtKeySpec privKeySpec = new RSAPrivateCrtKeySpec(
        new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
        new BigInteger("11", 16),
        new BigInteger("9f66f6b05410cd503b2709e88115d55daced94d1a34d4e32bf824d0dde6028ae79c5f07b580f5dce240d7111f7ddb130a7945cd7d957d1920994da389f490c89", 16),
        new BigInteger("c0a0758cdf14256f78d4708c86becdead1b50ad4ad6c5c703e2168fbf37884cb", 16),
        new BigInteger("f01734d7960ea60070f1b06f2bb81bfac48ff192ae18451d5e56c734a5aab8a5", 16),
        new BigInteger("b54bb9edff22051d9ee60f9351a48591b6500a319429c069a3e335a1d6171391", 16),
        new BigInteger("d3d83daf2a0cecd3367ae6f8ae1aeb82e9ac2f816c6fc483533d8297dd7884cd", 16),
        new BigInteger("b8f52fc6f38593dabb661d3f50f8897f8106eee68b1bce78a95b132b4e5b5d19", 16));

    private RSAPublicKeySpec isoPubKeySpec = new RSAPublicKeySpec(
        new BigInteger("0100000000000000000000000000000000bba2d15dbb303c8a21c5ebbcbae52b7125087920dd7cdf358ea119fd66fb064012ec8ce692f0a0b8e8321b041acd40b7", 16),
        new BigInteger("03", 16));

    private RSAPrivateKeySpec isoPrivKeySpec = new RSAPrivateKeySpec(
        new BigInteger("0100000000000000000000000000000000bba2d15dbb303c8a21c5ebbcbae52b7125087920dd7cdf358ea119fd66fb064012ec8ce692f0a0b8e8321b041acd40b7", 16),
        new BigInteger("2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac9f0783a49dd5f6c5af651f4c9d0dc9281c96a3f16a85f9572d7cc3f2d0f25a9dbf1149e4cdc32273faadd3fda5dcda7", 16));

    static RSAPublicKeySpec pub2048KeySpec = new RSAPublicKeySpec(
            new BigInteger("a7295693155b1813bb84877fb45343556e0568043de5910872a3a518cc11e23e2db74eaf4545068c4e3d258a2718fbacdcc3eafa457695b957e88fbf110aed049a992d9c430232d02f3529c67a3419935ea9b569f85b1bcd37de6b899cd62697e843130ff0529d09c97d813cb15f293751ff56f943fbdabb63971cc7f4f6d5bff1594416b1f5907bde5a84a44f9802ef29b43bda1960f948f8afb8766c1ab80d32eec88ed66d0b65aebe44a6d0b3c5e0ab051aaa1b912fbcc17b8e751ddecc5365b6db6dab0020c3057db4013a51213a5798a3aab67985b0f4d88627a54a0f3f0285fbcb4afdfeb65cb153af66825656d43238b75503231500753f4e421e3c57", 16),
            new BigInteger("10001", 16));

    static RSAPrivateCrtKeySpec priv2048KeySpec = new RSAPrivateCrtKeySpec(
            new BigInteger("a7295693155b1813bb84877fb45343556e0568043de5910872a3a518cc11e23e2db74eaf4545068c4e3d258a2718fbacdcc3eafa457695b957e88fbf110aed049a992d9c430232d02f3529c67a3419935ea9b569f85b1bcd37de6b899cd62697e843130ff0529d09c97d813cb15f293751ff56f943fbdabb63971cc7f4f6d5bff1594416b1f5907bde5a84a44f9802ef29b43bda1960f948f8afb8766c1ab80d32eec88ed66d0b65aebe44a6d0b3c5e0ab051aaa1b912fbcc17b8e751ddecc5365b6db6dab0020c3057db4013a51213a5798a3aab67985b0f4d88627a54a0f3f0285fbcb4afdfeb65cb153af66825656d43238b75503231500753f4e421e3c57", 16),
            new BigInteger("10001", 16),
            new BigInteger("65dad56ac7df7abb434e4cb5eeadb16093aa6da7f0033aad3815289b04757d32bfee6ade7749c8e4a323b5050a2fb9e2a99e23469e1ed4ba5bab54336af20a5bfccb8b3424cc6923db2ffca5787ed87aa87aa614cd04cedaebc8f623a2d2063017910f436dff18bb06f01758610787f8b258f0a8efd8bd7de30007c47b2a1031696c7d6523bc191d4d918927a7e0b09584ed205bd2ff4fc4382678df82353f7532b3bbb81d69e3f39070aed3fb64fce032a089e8e64955afa5213a6eb241231bd98d702fba725a9b205952fda186412d9e0d9344d2998c455ad8c2bae85ee672751466d5288304032b5b7e02f7e558c7af82c7fbf58eea0bb4ef0f001e6cd0a9", 16),
            new BigInteger("d4fd9ac3474fb83aaf832470643609659e511b322632b239b688f3cd2aad87527d6cf652fb9c9ca67940e84789444f2e99b0cb0cfabbd4de95396106c865f38e2fb7b82b231260a94df0e01756bf73ce0386868d9c41645560a81af2f53c18e4f7cdf3d51d80267372e6e0216afbf67f655c9450769cca494e4f6631b239ce1b", 16),
            new BigInteger("c8eaa0e2a1b3a4412a702bccda93f4d150da60d736c99c7c566fdea4dd1b401cbc0d8c063daaf0b579953d36343aa18b33dbf8b9eae94452490cc905245f8f7b9e29b1a288bc66731a29e1dd1a45c9fd7f8238ff727adc49fff73991d0dc096206b9d3a08f61e7462e2b804d78cb8c5eccdb9b7fbd2ad6a8fea46c1053e1be75", 16),
            new BigInteger("10edcb544421c0f9e123624d1099feeb35c72a8b34e008ac6fa6b90210a7543f293af4e5299c8c12eb464e70092805c7256e18e5823455ba0f504d36f5ccacac1b7cd5c58ff710f9c3f92646949d88fdd1e7ea5fed1081820bb9b0d2a8cd4b093fecfdb96dabd6e28c3a6f8c186dc86cddc89afd3e403e0fcf8a9e0bcb27af0b", 16),
            new BigInteger("97fc25484b5a415eaa63c03e6efa8dafe9a1c8b004d9ee6e80548fefd6f2ce44ee5cb117e77e70285798f57d137566ce8ea4503b13e0f1b5ed5ca6942537c4aa96b2a395782a4cb5b58d0936e0b0fa63b1192954d39ced176d71ef32c6f42c84e2e19f9d4dd999c2151b032b97bd22aa73fd8c5bcd15a2dca4046d5acc997021", 16),
            new BigInteger("4bb8064e1eff7e9efc3c4578fcedb59ca4aef0993a8312dfdcb1b3decf458aa6650d3d0866f143cbf0d3825e9381181170a0a1651eefcd7def786b8eb356555d9fa07c85b5f5cbdd74382f1129b5e36b4166b6cc9157923699708648212c484958351fdc9cf14f218dbe7fbf7cbd93a209a4681fe23ceb44bab67d66f45d1c9d", 16));

    static final byte[] pssPublicKey = Base64.decode("MIIBIDALBgkqhkiG9w0BAQoDggEPADCCAQoCggEBAJqAfazeBJT/qb6j+4Xck3V07pxMcsIUr8onGlhNW0b4XI5Wwxplg1MNB5EJGvdKIdQW5krd4FE8ltefbgUCjD028ALpQtOWoaccIxpptjD6lD8NyG1lVW96Oz9U+bq2nkgWH4B1aXZhrKOGq08bZSLj7Kq7wP1OCxhgSUI9iP+ketfLApH9OjUgMZY8/HOlwavy0yGvablJQbkDef+a4cMcptSSbgEbrZejfhIGYQ2XI1DDHJl2Bx4keOyG1HgC/EV+RmCp6pjhIs+kg45CPqznJqfeWQjo5hULXhr1Pj2B3Bvo1D5eOtrdfZg2p4XXpDVMV6MEiK9qQRONJ8gGC48CAwEAAQ==");
    static final byte[] pssPrivateKey = Base64.decode("MIIEvAIBADALBgkqhkiG9w0BAQoEggSoMIIEpAIBAAKCAQEAw0FMvJJ15M3aEwAEJToG90JRFhzVnMPw2aKD/xFXJUVuP/Iet/LoWECSokcbcwDVa3GVuQVEsU1/sMS2a5aFoB5NqvMx0vetsBC4X9t85zY5EdMKzEszXX71jzX/yl3YIiMPM0r39Bfu0H+Ixv0wnyrrol+QqkR7MklgfbP6I91FWbeubPGxmSxyQRcz1qS05mH+BXTQ3uwxCBwLo0WO1hovsOIfhFu993qCnK3Oy3jPDvauLj8Z0hIfrHCQNaIxZUcArELLirJsANfCuI4+XCYvMJxQkmrd3ciNWtQu0orSQtWaIVccT1FezOUrme+6tRpELS5VOxearj059qrLIwIDAQABAoIBAG02bCaZwUmefpjcDHWKFHVe6Z31uOG7k08YIL6dw2G8iSNJWTdIrf8W9y2/mjHkSHuVh8p6kOafU4nbLbHV+p4J9SVma/r1wHfXkllDmoR1Bszaf5KviWaFafKVoKJfhVHqzEjDaRdl/5UtkKLE4dpVloE29OLX9RS2iDsnXQWLdyg8ni1U7bjt3twV8sB/8YNx3aQ9rOb051FsKwBocoPVrw8J5A/mWk/6EvhOpf1ItotH/Sjw/w6qwl9tbEyInkBP1+L/AExlr4fipOxDImNkxfvO7ICOgbUSExvTd1uhsHdo9pkEFlvD9ilM71EnLBGOcnnUiOjyDh4wh+aasSkCgYEA6m2GiBx3rDnj+4fx7WhNyh/whvUnWCGIWJF0ctcSD8Ok5CXe8G2X+bVXUlzj3CRZBeCG5xYxsx+d4lzlrjgBidBsoeBLGcmq5v+kB3tpwZiLwyLTb33/LzT0lEjpZOqCx32n7GMeehjdtZE7eaXaGL9IJUjsYkwn6vMLIO+oaS8CgYEA1Tj4z0GkglpOemkw52+nkj9iMr3mdGYGmtSWpsu+fFbq6Fslk+gP5N6nDBzxbKadzqSFBNgNkZtm+/abZqql9rTxOC2guYuFS7a4Wjj1e5gYCNcE/EOIR0wbhO6zlqxuuqcqqWRyz9hPUZC662S4dIMxwvwXv5780oBMR2QVWE0CgYEA5swR6Sttvsf35om+62cHPvoXCieOJrxMyjXaGb4YcCDD1EJcrQSY3SVl5RbC1teKNbkJ17UIFTwJavTew5ksGoxyhySVi7v6YBZLXXppckpHP0SoOVooxEc0jFEER3CCdPkHPDmRpc+ZZ8qmbWuVv0uDMgILh/NGUZAa4sBQY80CgYEAgibYmYp0JK2DIe170ImzO+48vsR0G7D7bx89JmtPxw43LcYVVgddTFMsnJQ+OhgqU6zRFXfcMHkvj7WkfjLEQ6eHZsdTSG8F2oWaWlhSYDMi2KKHhISkdwDZ+3bJYLu4i27m96c8/eoH4L37mxxMC7LZeS/wPyOJJ+TwqtNIxDECgYAf52wVSjHEo9WwsCet4MJhWukLMBkyO2J9IIwsGGP5MyOTpqZN3OfL0g0Qe6oSbExafszuI5DBJNNBJAQqRC6fdhlqLNJEmgKPthbhi/pmqmfcCvbqt4UcEcDdhrrSLMK+4maZMQj7JqaSa+Tv2TYK+pK6D9BuXJRPsTiqBMkJZw==");

    public void performTest()
        throws Exception
    {
        KeyFactory          fact;
        byte[]              input = new byte[]
                                { (byte)0x54, (byte)0x85, (byte)0x9b, (byte)0x34, (byte)0x2c, (byte)0x49, (byte)0xea, (byte)0x2a };
        byte[][]            output = new byte[][]
                                {
                                    Hex.decode("8b427f781a2e59dd9def386f1956b996ee07f48c96880e65a368055ed8c0a8831669ef7250b40918b2b1d488547e72c84540e42bd07b03f14e226f04fbc2d929"),
                                    Hex.decode("2ec6e1a1711b6c7b8cd3f6a25db21ab8bb0a5f1d6df2ef375fa708a43997730ffc7c98856dbbe36edddcdd1b2d2a53867d8355af94fea3aeec128da908e08f4c"),
                                    Hex.decode("0850ac4e5a8118323200c8ed1e5aaa3d5e635172553ccac66a8e4153d35c79305c4440f11034ab147fccce21f18a50cf1c0099c08a577eb68237a91042278965"),
                                    Hex.decode("1c9649bdccb51056751fe43837f4eb43bada472accf26f65231666d5de7d11950d8379b3596dfdf75c6234274896fa8d18ad0865d3be2ac4d6687151abdf01e93941dcef18fa63186c9351d1506c89d09733c5ff4304208c812bdd21a50f56fde115e629e0e973721c9fcc87e89295a79853dee613962a0b2f2fc57163fd99057a3c776f13c20c26407eb8863998d7e53b543ba8d0a295a9a68d1a149833078c9809ad6a6dad7fc22a95ad615a73138c54c018f40d99bf8eeecd45f5be526f2d6b01aeb56381991c1ab31a2e756f15e052b9cd5638b2eff799795c5bae493307d5eb9f8c21d438de131fe505a4e7432547ab19224094f9e4be1968bd0793b79d"),
                                    Hex.decode("4c4afc0c24dddaedd4f9a3b23be30d35d8e005ffd36b3defc5d18acc830c3ed388ce20f43a00e614fd087c814197bc9fc2eff9ad4cc474a7a2ef3ed9c0f0a55eb23371e41ee8f2e2ed93ea3a06ca482589ab87e0d61dcffda5eea1241408e43ea1108726cdb87cc3aa5e9eaaa9f72507ca1352ac54a53920c94dccc768147933d8c50aefd9d1da10522a40133cd33dbc0524669e70f771a88d65c4716d471cd22b08b9f01f24e4e9fc7ffbcfa0e0a7aed47b345826399b26a73be112eb9c5e06fc6742fc3d0ef53d43896403c5105109cfc12e6deeaf4a48ba308e039774b9bdb31a9b9e133c81c321630cf0b4b2d1f90717b24c3268e1fea681ea9cdc709342"),
                                    Hex.decode("06b5b26bd13515f799e5e37ca43cace15cd82fd4bf36b25d285a6f0998d97c8cb0755a28f0ae66618b1cd03e27ac95eaaa4882bc6dc0078cd457d4f7de4154173a9c7a838cfc2ac2f74875df462aae0cfd341645dc51d9a01da9bdb01507f140fa8a016534379d838cc3b2a53ac33150af1b242fc88013cb8d914e66c8182864ee6de88ce2879d4c05dd125409620a96797c55c832fb2fb31d4310c190b8ed2c95fdfda2ed87f785002faaec3f35ec05cf70a3774ce185e4882df35719d582dd55ac31257344a9cba95189dcbea16e8c6cb7a235a0384bc83b6183ca8547e670fe33b1b91725ae0c250c9eca7b5ba78bd77145b70270bf8ac31653006c02ca9c"),
                                    Hex.decode("135f1be3d045526235bf9d5e43499d4ee1bfdf93370769ae56e85dbc339bc5b7ea3bee49717497ee8ac3f7cd6adb6fc0f17812390dcd65ac7b87fef7970d9ff9"),
                                    Hex.decode("03c05add1e030178c352face07cafc9447c8f369b8f95125c0d311c16b6da48ca2067104cce6cd21ae7b163cd18ffc13001aecebdc2eb02b9e92681f84033a98"),
                                    Hex.decode("00319bb9becb49f3ed1bca26d0fcf09b0b0a508e4d0bd43b350f959b72cd25b3af47d608fdcd248eada74fbe19990dbeb9bf0da4b4e1200243a14e5cab3f7e610c")
                                };
        SecureRandom        rand = new FixedSecureRandom();


        fact = KeyFactory.getInstance("RSA", "BC");

        PrivateKey  privKey = fact.generatePrivate(privKeySpec);
        PublicKey   pubKey = fact.generatePublic(pubKeySpec);
        
        PrivateKey  priv2048Key = fact.generatePrivate(priv2048KeySpec);
        PublicKey   pub2048Key = fact.generatePublic(pub2048KeySpec);

        // getKeySpec tests
        isTrue(fact.getKeySpec(privKey, KeySpec.class) instanceof RSAPrivateCrtKeySpec);
        isTrue(fact.getKeySpec(privKey, RSAPrivateKeySpec.class) instanceof RSAPrivateCrtKeySpec);
        isTrue(fact.getKeySpec(privKey, RSAPrivateCrtKeySpec.class) instanceof RSAPrivateCrtKeySpec);
        isTrue(fact.getKeySpec(privKey, OpenSSHPrivateKeySpec.class) instanceof OpenSSHPrivateKeySpec);

        RSAPrivateKey simpPriv = (RSAPrivateKey)fact.generatePrivate(new RSAPrivateKeySpec(privKeySpec.getPrivateExponent(), privKeySpec.getModulus()));

        isTrue(fact.getKeySpec(simpPriv, KeySpec.class) instanceof RSAPrivateKeySpec);
        isTrue(fact.getKeySpec(simpPriv, RSAPrivateKeySpec.class) instanceof RSAPrivateKeySpec);
        try
        {
            fact.getKeySpec(simpPriv, RSAPrivateCrtKeySpec.class);
        }
        catch (InvalidKeySpecException e)
        {
            // ignore
        }

        isTrue(fact.getKeySpec(pubKey, KeySpec.class) instanceof RSAPublicKeySpec);
        isTrue(fact.getKeySpec(pubKey, RSAPublicKeySpec.class) instanceof RSAPublicKeySpec);
        isTrue(fact.getKeySpec(pubKey, OpenSSHPublicKeySpec.class) instanceof OpenSSHPublicKeySpec);

        //
        // key without CRT coefficients
        //
        PrivateKeyInfo keyInfo = PrivateKeyInfo.getInstance(privKey.getEncoded());
        BigInteger zero = BigInteger.valueOf(0);
        PKCS8EncodedKeySpec noCrtSpec = new PKCS8EncodedKeySpec(new PrivateKeyInfo(keyInfo.getPrivateKeyAlgorithm(),
                                                   new org.bouncycastle.asn1.pkcs.RSAPrivateKey(privKeySpec.getModulus(), privKeySpec.getPublicExponent(), privKeySpec.getPrivateExponent(), zero, zero, zero, zero, zero)).getEncoded());

        PrivateKey noCrtKey = fact.generatePrivate(noCrtSpec);
        if (noCrtKey instanceof RSAPrivateCrtKey)
        {
            fail("private key without CRT coefficients returned as CRT key");
        }

        //
        // No Padding
        //
        Cipher c = Cipher.getInstance("RSA", "BC");

        c.init(Cipher.ENCRYPT_MODE, pubKey, rand);

        byte[]  out = c.doFinal(input);

        if (!areEqual(out, output[0]))
        {
            fail("NoPadding test failed on encrypt expected " + new String(Hex.encode(output[0])) + " got " + new String(Hex.encode(out)));
        }

        c.init(Cipher.DECRYPT_MODE, privKey);

        out = c.doFinal(out);

        if (!areEqual(out, input))
        {
            fail("NoPadding test failed on decrypt expected " + new String(Hex.encode(input)) + " got " + new String(Hex.encode(out)));
        }

        //
        // No Padding - incremental
        //
        c = Cipher.getInstance("RSA", "BC");

        c.init(Cipher.ENCRYPT_MODE, pubKey, rand);

        c.update(input);

        out = c.doFinal();

        if (!areEqual(out, output[0]))
        {
            fail("NoPadding test failed on encrypt expected " + new String(Hex.encode(output[0])) + " got " + new String(Hex.encode(out)));
        }

        c.init(Cipher.DECRYPT_MODE, privKey);

        out = c.doFinal(out);

        if (!areEqual(out, input))
        {
            fail("NoPadding test failed on decrypt expected " + new String(Hex.encode(input)) + " got " + new String(Hex.encode(out)));
        }

        //
        // No Padding - incremental - explicit use of NONE in mode.
        //
        c = Cipher.getInstance("RSA/NONE/NoPadding", "BC");

        c.init(Cipher.ENCRYPT_MODE, pubKey, rand);

        c.update(input);

        out = c.doFinal();

        if (!areEqual(out, output[0]))
        {
            fail("NoPadding test failed on encrypt expected " + new String(Hex.encode(output[0])) + " got " + new String(Hex.encode(out)));
        }

        c.init(Cipher.DECRYPT_MODE, privKey);

        out = c.doFinal(out);

        if (!areEqual(out, input))
        {
            fail("NoPadding test failed on decrypt expected " + new String(Hex.encode(input)) + " got " + new String(Hex.encode(out)));
        }

        //
        // No Padding - maximum length
        //
        c = Cipher.getInstance("RSA", "BC");

        byte[]  modBytes = ((RSAPublicKey)pubKey).getModulus().toByteArray();
        byte[]  maxInput = new byte[modBytes.length - 1];

        maxInput[0] |= 0x7f;

        c.init(Cipher.ENCRYPT_MODE, pubKey, rand);

        out = c.doFinal(maxInput);

        c.init(Cipher.DECRYPT_MODE, privKey);

        out = c.doFinal(out);

        if (!areEqual(out, maxInput))
        {
            fail("NoPadding test failed on decrypt expected " + new String(Hex.encode(maxInput)) + " got " + new String(Hex.encode(out)));
        }

        //
        // PKCS1 V 1.5
        //
        c = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");

        c.init(Cipher.ENCRYPT_MODE, pubKey, rand);

        out = c.doFinal(input);

        if (!areEqual(out, output[1]))
        {
            fail("PKCS1 test failed on encrypt expected " + new String(Hex.encode(output[1])) + " got " + new String(Hex.encode(out)));
        }

        c.init(Cipher.DECRYPT_MODE, privKey);

        out = c.doFinal(out);

        if (!areEqual(out, input))
        {
            fail("PKCS1 test failed on decrypt expected " + new String(Hex.encode(input)) + " got " + new String(Hex.encode(out)));
        }

        //
        // PKCS1 V 1.5 - NONE
        //
        c = Cipher.getInstance("RSA/NONE/PKCS1Padding", "BC");

        c.init(Cipher.ENCRYPT_MODE, pubKey, rand);

        out = c.doFinal(input);

        if (!areEqual(out, output[1]))
        {
            fail("PKCS1 test failed on encrypt expected " + new String(Hex.encode(output[1])) + " got " + new String(Hex.encode(out)));
        }

        c.init(Cipher.DECRYPT_MODE, privKey);

        out = c.doFinal(out);

        if (!areEqual(out, input))
        {
            fail("PKCS1 test failed on decrypt expected " + new String(Hex.encode(input)) + " got " + new String(Hex.encode(out)));
        }

        //
        // OAEP - SHA1
        //
        c = Cipher.getInstance("RSA/NONE/OAEPPadding", "BC");

        c.init(Cipher.ENCRYPT_MODE, pubKey, rand);

        out = c.doFinal(input);

        if (!areEqual(out, output[2]))
        {
            fail("OAEP test failed on encrypt expected " + new String(Hex.encode(output[2])) + " got " + new String(Hex.encode(out)));
        }

        c = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", "BC");
        
        c.init(Cipher.DECRYPT_MODE, privKey);

        out = c.doFinal(out);

        if (!areEqual(out, input))
        {
            fail("OAEP test failed on decrypt expected " + new String(Hex.encode(input)) + " got " + new String(Hex.encode(out)));
        }
        
        AlgorithmParameters oaepP = c.getParameters();
        
        if (!areEqual(oaepP.getEncoded(), 
                new RSAESOAEPparams(
                        new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE), 
                        new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE)),
                        new AlgorithmIdentifier(PKCSObjectIdentifiers.id_pSpecified, new DEROctetString(new byte[0]))).getEncoded()))
        {
            fail("OAEP test failed default sha-1 parameters");
        }
        
        //
        // OAEP - SHA224
        //
        c = Cipher.getInstance("RSA/NONE/OAEPWithSHA224AndMGF1Padding", "BC");

        c.init(Cipher.ENCRYPT_MODE, pub2048Key, rand);

        out = c.doFinal(input);

        if (!areEqual(out, output[3]))
        {
            fail("OAEP SHA-224 test failed on encrypt expected " + new String(Hex.encode(output[2])) + " got " + new String(Hex.encode(out)));
        }

        c.init(Cipher.DECRYPT_MODE, priv2048Key);

        out = c.doFinal(out);

        if (!areEqual(out, input))
        {
            fail("OAEP SHA-224 test failed on decrypt expected " + new String(Hex.encode(input)) + " got " + new String(Hex.encode(out)));
        }
        
        oaepP = c.getParameters();
        
        if (!areEqual(oaepP.getEncoded(), 
                new RSAESOAEPparams(
                        new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha224, DERNull.INSTANCE), 
                        new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha224, DERNull.INSTANCE)),
                        new AlgorithmIdentifier(PKCSObjectIdentifiers.id_pSpecified, new DEROctetString(new byte[0]))).getEncoded()))
        {
            fail("OAEP test failed default sha-224 parameters");
        }
        
        //
        // OAEP - SHA 256
        //
        c = Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding", "BC");

        c.init(Cipher.ENCRYPT_MODE, pub2048Key, rand);

        out = c.doFinal(input);

        if (!areEqual(out, output[4]))
        {
            fail("OAEP SHA-256 test failed on encrypt expected " + new String(Hex.encode(output[2])) + " got " + new String(Hex.encode(out)));
        }

        c.init(Cipher.DECRYPT_MODE, priv2048Key);

        out = c.doFinal(out);

        if (!areEqual(out, input))
        {
            fail("OAEP SHA-256 test failed on decrypt expected " + new String(Hex.encode(input)) + " got " + new String(Hex.encode(out)));
        }
        
        oaepP = c.getParameters();
        
        if (!areEqual(oaepP.getEncoded(), 
                new RSAESOAEPparams(
                        new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE), 
                        new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE)),
                        new AlgorithmIdentifier(PKCSObjectIdentifiers.id_pSpecified, new DEROctetString(new byte[0]))).getEncoded()))
        {
            fail("OAEP test failed default sha-256 parameters");
        }
        
        //
        // OAEP - SHA 384
        //
        c = Cipher.getInstance("RSA/NONE/OAEPWithSHA384AndMGF1Padding", "BC");

        c.init(Cipher.ENCRYPT_MODE, pub2048Key, rand);

        out = c.doFinal(input);

        if (!areEqual(out, output[5]))
        {
            fail("OAEP SHA-384 test failed on encrypt expected " + new String(Hex.encode(output[2])) + " got " + new String(Hex.encode(out)));
        }

        c.init(Cipher.DECRYPT_MODE, priv2048Key);

        out = c.doFinal(out);

        if (!areEqual(out, input))
        {
            fail("OAEP SHA-384 test failed on decrypt expected " + new String(Hex.encode(input)) + " got " + new String(Hex.encode(out)));
        }
        
        oaepP = c.getParameters();
        
        if (!areEqual(oaepP.getEncoded(), 
                new RSAESOAEPparams(
                        new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384, DERNull.INSTANCE), 
                        new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384, DERNull.INSTANCE)),
                        new AlgorithmIdentifier(PKCSObjectIdentifiers.id_pSpecified, new DEROctetString(new byte[0]))).getEncoded()))
        {
            fail("OAEP test failed default sha-384 parameters");
        }
        
        //
        // OAEP - MD5
        //
        c = Cipher.getInstance("RSA/NONE/OAEPWithMD5AndMGF1Padding", "BC");

        c.init(Cipher.ENCRYPT_MODE, pubKey, rand);

        out = c.doFinal(input);

        if (!areEqual(out, output[6]))
        {
            fail("OAEP MD5 test failed on encrypt expected " + new String(Hex.encode(output[2])) + " got " + new String(Hex.encode(out)));
        }

        c.init(Cipher.DECRYPT_MODE, privKey);

        out = c.doFinal(out);

        if (!areEqual(out, input))
        {
            fail("OAEP MD5 test failed on decrypt expected " + new String(Hex.encode(input)) + " got " + new String(Hex.encode(out)));
        }
        
        oaepP = c.getParameters();
        
        if (!areEqual(oaepP.getEncoded(), 
                new RSAESOAEPparams(
                        new AlgorithmIdentifier(PKCSObjectIdentifiers.md5, DERNull.INSTANCE), 
                        new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, new AlgorithmIdentifier(PKCSObjectIdentifiers.md5, DERNull.INSTANCE)),
                        new AlgorithmIdentifier(PKCSObjectIdentifiers.id_pSpecified, new DEROctetString(new byte[0]))).getEncoded()))
        {
            fail("OAEP test failed default md5 parameters");
        }
        
        //
        // OAEP - SHA1 with default parameters
        //
        c = Cipher.getInstance("RSA/NONE/OAEPPadding", "BC");

        c.init(Cipher.ENCRYPT_MODE, pubKey, OAEPParameterSpec.DEFAULT, rand);

        out = c.doFinal(input);

        if (!areEqual(out, output[2]))
        {
            fail("OAEP test failed on encrypt expected " + new String(Hex.encode(output[2])) + " got " + new String(Hex.encode(out)));
        }

        c = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", "BC");
        
        c.init(Cipher.DECRYPT_MODE, privKey);

        out = c.doFinal(out);
        
        if (!areEqual(out, input))
        {
            fail("OAEP test failed on decrypt expected " + new String(Hex.encode(input)) + " got " + new String(Hex.encode(out)));
        }
        
        oaepP = c.getParameters();
        
        if (!areEqual(oaepP.getEncoded(), new byte[] { 0x30, 0x00 }))
        {
            fail("OAEP test failed default parameters");
        }

        //
        // OAEP - SHA1 with specified string
        //
        c = Cipher.getInstance("RSA/NONE/OAEPPadding", "BC");

        c.init(Cipher.ENCRYPT_MODE, pubKey, new OAEPParameterSpec("SHA1", "MGF1", new MGF1ParameterSpec("SHA1"), new PSource.PSpecified(new byte[] { 1, 2, 3, 4, 5 })), rand);

        out = c.doFinal(input);

        oaepP = c.getParameters();
        
        if (!areEqual(oaepP.getEncoded(), 
                new RSAESOAEPparams(
                        new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE), 
                        new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE)),
                        new AlgorithmIdentifier(PKCSObjectIdentifiers.id_pSpecified, new DEROctetString(new byte[] { 1, 2, 3, 4, 5 }))).getEncoded()))
        {
            fail("OAEP test failed changed sha-1 parameters");
        }
        
        if (!areEqual(out, output[7]))
        {
            fail("OAEP test failed on encrypt expected " + new String(Hex.encode(output[2])) + " got " + new String(Hex.encode(out)));
        }

        c = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", "BC");
        
        c.init(Cipher.DECRYPT_MODE, privKey, oaepP);

        out = c.doFinal(out);

        if (!areEqual(out, input))
        {
            fail("OAEP test failed on decrypt expected " + new String(Hex.encode(input)) + " got " + new String(Hex.encode(out)));
        }
        
        //
        // ISO9796-1
        //
        byte[]      isoInput =  Hex.decode("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210");
        PrivateKey  isoPrivKey = fact.generatePrivate(isoPrivKeySpec);
        PublicKey   isoPubKey = fact.generatePublic(isoPubKeySpec);

        c = Cipher.getInstance("RSA/NONE/ISO9796-1Padding", "BC");

        c.init(Cipher.ENCRYPT_MODE, isoPrivKey);

        out = c.doFinal(isoInput);

        if (!areEqual(out, output[8]))
        {
            fail("ISO9796-1 test failed on encrypt expected " + new String(Hex.encode(output[3])) + " got " + new String(Hex.encode(out)));
        }

        c.init(Cipher.DECRYPT_MODE, isoPubKey);

        out = c.doFinal(out);

        if (!areEqual(out, isoInput))
        {
            fail("ISO9796-1 test failed on decrypt expected " + new String(Hex.encode(input)) + " got " + new String(Hex.encode(out)));
        }

        //
        //
        // generation with parameters test.
        //
        KeyPairGenerator keyPairGen =
                KeyPairGenerator.getInstance("RSA", "BC");

        //
        // 768 bit RSA with e = 2^16-1
        //
        keyPairGen.initialize(
            new RSAKeyGenParameterSpec(768,
            BigInteger.valueOf(65537)),
            new SecureRandom());

        KeyPair kp = keyPairGen.generateKeyPair();

        pubKey = kp.getPublic();
        privKey = kp.getPrivate();

        c.init(Cipher.ENCRYPT_MODE, pubKey, rand);

        out = c.doFinal(input);

        c.init(Cipher.DECRYPT_MODE, privKey);

        out = c.doFinal(out);

        if (!areEqual(out, input))
        {
            fail("key generation test failed on decrypt expected " + new String(Hex.encode(input)) + " got " + new String(Hex.encode(out)));
        }

        //
        // comparison check
        //
        KeyFactory keyFact = KeyFactory.getInstance("RSA", "BC");
        
        RSAPrivateCrtKey crtKey = (RSAPrivateCrtKey)keyFact.translateKey(privKey);
        
        if (!privKey.equals(crtKey))
        {
            fail("private key equality check failed");
        }

        crtKey = (RSAPrivateCrtKey)keyFact.generatePrivate(new PKCS8EncodedKeySpec(privKey.getEncoded()));

        if (!privKey.equals(crtKey))
        {
            fail("private key equality check failed");
        }

        crtKey = (RSAPrivateCrtKey)serializeDeserialize(privKey);

        if (!privKey.equals(crtKey))
        {
            fail("private key equality check failed");
        }

        if (privKey.hashCode() != crtKey.hashCode())
        {
            fail("private key hashCode check failed");
        }

        if (!Arrays.areEqual(privKey.getEncoded(), crtKey.getEncoded()))
        {
            fail("encoding does not match");
        }

        RSAPublicKey copyKey = (RSAPublicKey)keyFact.translateKey(pubKey);
        
        if (!pubKey.equals(copyKey))
        {
            fail("public key equality check failed");
        }

        copyKey = (RSAPublicKey)keyFact.generatePublic(new X509EncodedKeySpec(pubKey.getEncoded()));

        if (!pubKey.equals(copyKey))
        {
            fail("public key equality check failed");
        }

        copyKey = (RSAPublicKey)serializeDeserialize(pubKey);

        if (!pubKey.equals(copyKey))
        {
            fail("public key equality check failed");
        }

        if (pubKey.hashCode() != copyKey.hashCode())
        {
            fail("public key hashCode check failed");
        }

        //
        // test an OAEP key
        //
        SubjectPublicKeyInfo oaepKey = new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP, new RSAESOAEPparams()),
                                                  SubjectPublicKeyInfo.getInstance(pubKey.getEncoded()).parsePublicKey());

        copyKey = (RSAPublicKey)serializeDeserialize(keyFact.generatePublic(new X509EncodedKeySpec(oaepKey.getEncoded())));

        if (!pubKey.equals(copyKey))
        {
            fail("public key equality check failed");
        }

        if (pubKey.hashCode() != copyKey.hashCode())
        {
            fail("public key hashCode check failed");
        }

        if (!Arrays.areEqual(copyKey.getEncoded(), oaepKey.getEncoded()))
        {
            fail("encoding does not match");
        }

        oaepCompatibilityTest("SHA-1", priv2048Key, pub2048Key);
        // TODO: oaepCompatibilityTest("SHA-224", priv2048Key, pub2048Key);      commented out as fails in JDK 1.7
        oaepCompatibilityTest("SHA-256", priv2048Key, pub2048Key);
        oaepCompatibilityTest("SHA-384", priv2048Key, pub2048Key);
        oaepCompatibilityTest("SHA-512", priv2048Key, pub2048Key);

        SecureRandom random = new SecureRandom();
        rawModeTest("SHA1withRSA", X509ObjectIdentifiers.id_SHA1, priv2048Key, pub2048Key, random);
        rawModeTest("MD5withRSA", PKCSObjectIdentifiers.md5, priv2048Key, pub2048Key, random);
        rawModeTest("RIPEMD128withRSA", TeleTrusTObjectIdentifiers.ripemd128, priv2048Key, pub2048Key, random);

        // init reset test
        c.init(Cipher.ENCRYPT_MODE, pubKey, rand);

        out = c.update(new byte[40]);

        c.init(Cipher.ENCRYPT_MODE, pubKey, rand);

        out = c.update(new byte[40]);

        testGetExceptionsPKCS1();
        zeroMessageTest();

        oaepDigestCheck("SHA3-224", NISTObjectIdentifiers.id_sha3_224, pub2048Key, priv2048Key, rand, Hex.decode("2aa7812d4f7b7766f8625feb58481ef5b5fa6dfafbea543e4bbba89d6708f4900fc9fd55d5c2b83fefefc67e2ba7a4222217efaa9b9d31920bdcd78733319aca910dfd118aae5e901a6d27a56e37b1a6f86e7404f82da248e77845e58b789f10a1af8a1208f77dda384692609339346c4ea57928b890042e7d70b1d5817f8978dcbc9cd2fcdde37a0a41a52dbef701ddc859a5d58efd10aa5bd8d205c10154db906540bf20dedcff721df11a456df201cb9cbbd092a89a1eb3f11e7e34003d7070e02c8db54e5498e7ee262fb9178f5eb85d1db66baafe0a66e8283df9c41bded218e5d906d28f08803deb3cbd1a92777d55fe56ff022a47f673cac2ca145973"));
        oaepDigestCheck("SHA3-256", NISTObjectIdentifiers.id_sha3_256, pub2048Key, priv2048Key, rand, Hex.decode("4460e68586ac0ca1832274919c6b9159d40ea1d383a32ca28f0e1a81962289c8c904fa117d90afd7bfefa51b6889d2d999efb72bafd4beb5594bb08f62532ecb077e4968f43e70673341e60649ed64ac49cf1a2396a64577767d8958217a251938a7ac1bbc1aec9c9197a2eb9a375c74a01097fe3717c8bde04f8a20df85ef10a59070970a4a6470131654cecb641d46e464f17ddfe7e0595025bf25f025edbd56b19487cfc87de1642ca5190f289cf78e2c4b1cf90e73ffae331581c23febcf490c32299f2e5bd5a354a0cc996cc692b5a318777d17e734b3c487ad615df7af0fc361af564e6970ee0aa9b140634cdcf1eda91d1a1156326caaa608c4d43ee4"));
        oaepDigestCheck("SHA3-384", NISTObjectIdentifiers.id_sha3_384, pub2048Key, priv2048Key, rand, Hex.decode("1b9f490569bddac8ea77e3bec8d6d38b159cb88545de86065dbc8757b35fdeb0cce90eaf93ec6d69d691c590fc3feec9974b80e0c0068929c77533be2066b4002ad6d195e473f72e8581255b8d2dfff016ff27ed50e6d3e63cfaf50851b2d43833eea8dab3b4506f517875659099815a96be6e8fd2dc1417c6e3ffadcfd3f494a5544267688d114d3eeaf43ea954686656afb7a3dc2f8a4cdc5d7b90a97acbbe32ff17b3d26d7eb2a4fbc847d49cc8cb8f837646613d1b5a78096cf3f48acf4be95205e0c4cb283447029eae1442fe3813a017604dfd59a9e841473f4d8914860f785fb2194b21cba47cd401bc32720f3df373e59336c3d64c61babd474b4bbe"));
        oaepDigestCheck("SHA3-512", NISTObjectIdentifiers.id_sha3_512, pub2048Key, priv2048Key, rand, Hex.decode("7b7870bb5ae52276a8b06b59f7321043afb1fa4e5dbca9f14bcce9efaacded531f090646ab0f8701b012cc93c51e0a8591043e6457cde1950f4ffc8ad87d946622ea48a70f95f40c22d88679eb92c10c19db487fd64857d723daf4ccfe749fdd05e6c0be28de57e09d3b5a0981322b6cc7a9743a50eec355a7af5bdcdcddc5e279ad90f599b68c47fdb39916c7a597cf989169e8667fd8602e88c9c128085d0e158ea75eeb37919a91cdf3f2cd5394adaadc4a2f25a6222d2637cb464841dc5820e54843495cb97af6b19edc72f137123813f5d78503232f79e4f617be3a9f09b0206634a2ecfe457dbd71d2d3d8e3dbca486e75e543f559dcea3112ad50a21d"));

        testPSSKeys();
    }

    private void testPSSKeys()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSASSA-PSS", "BC");

        isTrue("RSASSA-PSS".equals(kpGen.getAlgorithm()));
        
        KeyPair kp = kpGen.generateKeyPair();

        isTrue("RSASSA-PSS".equals(kp.getPublic().getAlgorithm()));
        isTrue("RSASSA-PSS".equals(kp.getPrivate().getAlgorithm()));

        KeyFactory kFact = KeyFactory.getInstance("RSASSA-PSS", "BC");

        isTrue("RSASSA-PSS".equals(kFact.getAlgorithm()));

        PublicKey publicKey = kFact.generatePublic(new X509EncodedKeySpec(pssPublicKey));

        isTrue("RSASSA-PSS".equals(publicKey.getAlgorithm()));

        PrivateKey privateKey = kFact.generatePrivate(new PKCS8EncodedKeySpec(pssPrivateKey));

        isTrue("RSASSA-PSS".equals(privateKey.getAlgorithm()));

        publicKey = kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        isTrue("RSASSA-PSS".equals(publicKey.getAlgorithm()));

        privateKey = kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        isTrue("RSASSA-PSS".equals(privateKey.getAlgorithm()));

        privateKey = (PrivateKey)serializeDeserialize(kp.getPrivate());

        isTrue(Arrays.areEqual(kp.getPrivate().getEncoded(), privateKey.getEncoded()));

        SubjectPublicKeyInfo subKey = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

        isTrue(null == subKey.getAlgorithm().getParameters());

        PrivateKeyInfo privKey = PrivateKeyInfo.getInstance(privateKey.getEncoded());

        isTrue(null == privKey.getPrivateKeyAlgorithm().getParameters());
    }

    public void oaepDigestCheck(String digest, ASN1ObjectIdentifier oid, PublicKey pubKey, PrivateKey privKey, SecureRandom rand, byte[] expected)
        throws Exception
    {
        byte[] input = new byte[]
            {(byte)0x54, (byte)0x85, (byte)0x9b, (byte)0x34, (byte)0x2c, (byte)0x49, (byte)0xea, (byte)0x2a};

        Cipher c = Cipher.getInstance("RSA/NONE/OAEPPadding", "BC");

        c.init(Cipher.ENCRYPT_MODE, pubKey, new OAEPParameterSpec(digest, "MGF1", new MGF1ParameterSpec(digest), PSource.PSpecified.DEFAULT), rand);

        byte[] out = c.doFinal(input);

        isTrue("OAEP decrypt failed", Arrays.areEqual(expected, out));

        AlgorithmParameters oaepP = c.getParameters();

        if (!areEqual(oaepP.getEncoded(),
            new RSAESOAEPparams(
                new AlgorithmIdentifier(oid, DERNull.INSTANCE),
                new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, new AlgorithmIdentifier(oid, DERNull.INSTANCE)),
                new AlgorithmIdentifier(PKCSObjectIdentifiers.id_pSpecified, new DEROctetString(new byte[0]))).getEncoded()))
        {
            fail("OAEP test failed changed parameters for " + digest);
        }

        c = Cipher.getInstance("RSA/NONE/OAEPWith" + digest + "AndMGF1Padding", "BC");

        c.init(Cipher.DECRYPT_MODE, privKey);

        byte[] dec = c.doFinal(out);

        isTrue("OAEP decrypt failed", Arrays.areEqual(input, dec));

        AlgorithmParameters parameters = AlgorithmParameters.getInstance("OAEP", "BC");

        parameters.init(oaepP.getEncoded());

        OAEPParameterSpec spec = (OAEPParameterSpec)parameters.getParameterSpec(OAEPParameterSpec.class);

        isTrue("Digest mismatch", digest.equals(spec.getDigestAlgorithm()));
        isTrue("MGF alg mismatch", OAEPParameterSpec.DEFAULT.getMGFAlgorithm().equals(spec.getMGFAlgorithm()));
        isTrue("MGF Digest mismatch", digest.equals(((MGF1ParameterSpec)spec.getMGFParameters()).getDigestAlgorithm()));

    }

    public void testGetExceptionsPKCS1()
        throws Exception
    {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA", "BC");
        keygen.initialize(1024);
        KeyPair keypair = keygen.genKeyPair();
        SecureRandom rand = new SecureRandom();
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        byte[] ciphertext = new byte[1024 / 8];
        HashSet<String> exceptions = new HashSet<String>();
        final int SAMPLES = 1000;
        for (int i = 0; i < SAMPLES; i++)
        {
            rand.nextBytes(ciphertext);
            ciphertext[0] = (byte)0;
            try
            {
                c.init(Cipher.DECRYPT_MODE, keypair.getPrivate());
                c.doFinal(ciphertext);
            }
            catch (Exception ex)
            {
                String message = ex.toString();
                exceptions.add(message);
            }
        }
        isTrue("exception count wrong", 1 == exceptions.size());
    }

    public void zeroMessageTest()
        throws Exception
    {
        KeyPairGenerator kgen = KeyPairGenerator.getInstance("RSA", "BC");

        RSAKeyGenParameterSpec rsaSpec = new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4);

        kgen.initialize(rsaSpec);

        KeyPair kp = kgen.generateKeyPair();

        byte[] plain = new byte[0];

        Cipher rsaCipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", "BC");
        rsaCipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());
        byte[] encrypted = rsaCipher.doFinal(plain);

        rsaCipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", "BC");
        rsaCipher.init(Cipher.DECRYPT_MODE, kp.getPrivate());
        byte[] decrypted  = rsaCipher.doFinal(encrypted);

        isTrue("zero mismatch", Arrays.areEqual(plain, decrypted));
    }

    private void oaepCompatibilityTest(String digest, PrivateKey privKey, PublicKey pubKey)
        throws Exception
    {
        if (Security.getProvider("SunJCE") == null || Security.getProvider("SunRsaSign") == null)
        {
            return;
        }

        KeyFactory  fact = KeyFactory.getInstance("RSA", "SunRsaSign");
        PrivateKey  priv2048Key = fact.generatePrivate(priv2048KeySpec);
        PublicKey   pub2048Key = fact.generatePublic(pub2048KeySpec);

        byte[] data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

        Cipher sCipher;
        try
        {
            sCipher = Cipher.getInstance("RSA/ECB/OAEPWith" + digest + "AndMGF1Padding", "SunJCE");
        }
        catch (NoSuchAlgorithmException e)
        {
            return;
        }
        catch (NoSuchPaddingException e)
        {
            return;
        }

        sCipher.init(Cipher.ENCRYPT_MODE, pub2048Key);

        byte[] enctext = sCipher.doFinal(data);

        Cipher bcCipher = Cipher.getInstance("RSA/ECB/OAEPWith" + digest + "AndMGF1Padding", "BC");

        bcCipher.init(Cipher.DECRYPT_MODE, privKey, new OAEPParameterSpec(digest, "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT));

        byte[] plaintext = bcCipher.doFinal(enctext);

        if (!Arrays.areEqual(plaintext, data))
        {
            fail("data did not decrypt first time");
        }

        bcCipher.init(Cipher.ENCRYPT_MODE, pubKey, new OAEPParameterSpec(digest, "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT));

        enctext = bcCipher.doFinal(data);

        sCipher.init(Cipher.DECRYPT_MODE, priv2048Key);

        plaintext = sCipher.doFinal(enctext);

        if (!Arrays.areEqual(plaintext, data))
        {
            fail("data did not decrypt second time");
        }
    }

    private void rawModeTest(String sigName, ASN1ObjectIdentifier digestOID,
        PrivateKey privKey, PublicKey pubKey, SecureRandom random) throws Exception
    {
        byte[] sampleMessage = new byte[1000 + random.nextInt(100)];
        random.nextBytes(sampleMessage);

        Signature normalSig = Signature.getInstance(sigName, "BC");
        normalSig.initSign(privKey);
        normalSig.update(sampleMessage);
        byte[] normalResult = normalSig.sign();

        MessageDigest digest = MessageDigest.getInstance(digestOID.getId(), "BC");
        byte[] hash = digest.digest(sampleMessage);
        byte[] digInfo = derEncode(digestOID, hash);

        Signature rawSig = Signature.getInstance("RSA", "BC");
        rawSig.initSign(privKey);
        rawSig.update(digInfo);
        byte[] rawResult = rawSig.sign();

        if (!Arrays.areEqual(normalResult, rawResult))
        {
            fail("raw mode signature differs from normal one");
        }

        rawSig.initVerify(pubKey);
        rawSig.update(digInfo);

        if (!rawSig.verify(rawResult))
        {
            fail("raw mode signature verification failed");
        }
    }

    private Object serializeDeserialize(Object o)
        throws Exception
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(o);
        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        return oIn.readObject();
    }

    private byte[] derEncode(ASN1ObjectIdentifier oid, byte[] hash) throws IOException
    {
        AlgorithmIdentifier algId = new AlgorithmIdentifier(oid, DERNull.INSTANCE);
        DigestInfo dInfo = new DigestInfo(algId, hash);

        return dInfo.getEncoded(ASN1Encoding.DER);
    }

    public String getName()
    {
        return "RSATest";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new RSATest());
    }
}
