package org.bouncycastle.jce.provider.test;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Set;
import java.util.HashSet;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
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

    private RSAPublicKeySpec pub2048KeySpec = new RSAPublicKeySpec(
            new BigInteger("a7295693155b1813bb84877fb45343556e0568043de5910872a3a518cc11e23e2db74eaf4545068c4e3d258a2718fbacdcc3eafa457695b957e88fbf110aed049a992d9c430232d02f3529c67a3419935ea9b569f85b1bcd37de6b899cd62697e843130ff0529d09c97d813cb15f293751ff56f943fbdabb63971cc7f4f6d5bff1594416b1f5907bde5a84a44f9802ef29b43bda1960f948f8afb8766c1ab80d32eec88ed66d0b65aebe44a6d0b3c5e0ab051aaa1b912fbcc17b8e751ddecc5365b6db6dab0020c3057db4013a51213a5798a3aab67985b0f4d88627a54a0f3f0285fbcb4afdfeb65cb153af66825656d43238b75503231500753f4e421e3c57", 16),
            new BigInteger("10001", 16));

    private RSAPrivateCrtKeySpec priv2048KeySpec = new RSAPrivateCrtKeySpec(
            new BigInteger("a7295693155b1813bb84877fb45343556e0568043de5910872a3a518cc11e23e2db74eaf4545068c4e3d258a2718fbacdcc3eafa457695b957e88fbf110aed049a992d9c430232d02f3529c67a3419935ea9b569f85b1bcd37de6b899cd62697e843130ff0529d09c97d813cb15f293751ff56f943fbdabb63971cc7f4f6d5bff1594416b1f5907bde5a84a44f9802ef29b43bda1960f948f8afb8766c1ab80d32eec88ed66d0b65aebe44a6d0b3c5e0ab051aaa1b912fbcc17b8e751ddecc5365b6db6dab0020c3057db4013a51213a5798a3aab67985b0f4d88627a54a0f3f0285fbcb4afdfeb65cb153af66825656d43238b75503231500753f4e421e3c57", 16),
            new BigInteger("10001", 16),
            new BigInteger("65dad56ac7df7abb434e4cb5eeadb16093aa6da7f0033aad3815289b04757d32bfee6ade7749c8e4a323b5050a2fb9e2a99e23469e1ed4ba5bab54336af20a5bfccb8b3424cc6923db2ffca5787ed87aa87aa614cd04cedaebc8f623a2d2063017910f436dff18bb06f01758610787f8b258f0a8efd8bd7de30007c47b2a1031696c7d6523bc191d4d918927a7e0b09584ed205bd2ff4fc4382678df82353f7532b3bbb81d69e3f39070aed3fb64fce032a089e8e64955afa5213a6eb241231bd98d702fba725a9b205952fda186412d9e0d9344d2998c455ad8c2bae85ee672751466d5288304032b5b7e02f7e558c7af82c7fbf58eea0bb4ef0f001e6cd0a9", 16),
            new BigInteger("d4fd9ac3474fb83aaf832470643609659e511b322632b239b688f3cd2aad87527d6cf652fb9c9ca67940e84789444f2e99b0cb0cfabbd4de95396106c865f38e2fb7b82b231260a94df0e01756bf73ce0386868d9c41645560a81af2f53c18e4f7cdf3d51d80267372e6e0216afbf67f655c9450769cca494e4f6631b239ce1b", 16),
            new BigInteger("c8eaa0e2a1b3a4412a702bccda93f4d150da60d736c99c7c566fdea4dd1b401cbc0d8c063daaf0b579953d36343aa18b33dbf8b9eae94452490cc905245f8f7b9e29b1a288bc66731a29e1dd1a45c9fd7f8238ff727adc49fff73991d0dc096206b9d3a08f61e7462e2b804d78cb8c5eccdb9b7fbd2ad6a8fea46c1053e1be75", 16),
            new BigInteger("10edcb544421c0f9e123624d1099feeb35c72a8b34e008ac6fa6b90210a7543f293af4e5299c8c12eb464e70092805c7256e18e5823455ba0f504d36f5ccacac1b7cd5c58ff710f9c3f92646949d88fdd1e7ea5fed1081820bb9b0d2a8cd4b093fecfdb96dabd6e28c3a6f8c186dc86cddc89afd3e403e0fcf8a9e0bcb27af0b", 16),
            new BigInteger("97fc25484b5a415eaa63c03e6efa8dafe9a1c8b004d9ee6e80548fefd6f2ce44ee5cb117e77e70285798f57d137566ce8ea4503b13e0f1b5ed5ca6942537c4aa96b2a395782a4cb5b58d0936e0b0fa63b1192954d39ced176d71ef32c6f42c84e2e19f9d4dd999c2151b032b97bd22aa73fd8c5bcd15a2dca4046d5acc997021", 16),
            new BigInteger("4bb8064e1eff7e9efc3c4578fcedb59ca4aef0993a8312dfdcb1b3decf458aa6650d3d0866f143cbf0d3825e9381181170a0a1651eefcd7def786b8eb356555d9fa07c85b5f5cbdd74382f1129b5e36b4166b6cc9157923699708648212c484958351fdc9cf14f218dbe7fbf7cbd93a209a4681fe23ceb44bab67d66f45d1c9d", 16));

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
                                    Hex.decode("00319bb9becb49f3ed1bca26d0fcf09b0b0a508e4d0bd43b350f959b72cd25b3af47d608fdcd248eada74fbe19990dbeb9bf0da4b4e1200243a14e5cab3f7e610c")
                                };
        SecureRandom        rand = new FixedSecureRandom();


        fact = KeyFactory.getInstance("RSA", "BC");

        PrivateKey  privKey = fact.generatePrivate(privKeySpec);
        PublicKey   pubKey = fact.generatePublic(pubKeySpec);
        
        PrivateKey  priv2048Key = fact.generatePrivate(priv2048KeySpec);
        PublicKey   pub2048Key = fact.generatePublic(pub2048KeySpec);

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
            fail("NoPadding test failed on decrypt expected " + new String(Hex.encode(input)) + " got " + new String(Hex.encode(out)));
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
        
        //
        // ISO9796-1
        //
        byte[]      isoInput =  Hex.decode("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210");
        PrivateKey  isoPrivKey = fact.generatePrivate(isoPrivKeySpec);
        PublicKey   isoPubKey = fact.generatePublic(isoPubKeySpec);

        c = Cipher.getInstance("RSA/NONE/ISO9796-1Padding", "BC");

        c.init(Cipher.ENCRYPT_MODE, isoPrivKey);

        out = c.doFinal(isoInput);

        if (!areEqual(out, output[7]))
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

        testGetExceptionsPKCS1();
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
