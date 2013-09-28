package org.bouncycastle.jce.provider.test;

import java.security.MessageDigest;
import java.security.Security;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jcajce.spec.SkeinParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class SkeinTest
    extends SimpleTest
{
    final static String provider = "BC";

    static private byte[] nullMsg = new byte[0];

    static private String[][] nullVectors =
    {
        { "Skein-256-128", "07e8ff2191c5052e1a25914c7c213078" },
        { "Skein-256-160", "ff800bed6d2044ee9d604a674e3fda50d9b24a72" },
        { "Skein-256-224", "0fadf1fa39e3837a95b3660b4184d9c2f3cfc94b55d8e7a083278bf8" },
        { "Skein-256-256", "c8877087da56e072870daa843f176e9453115929094c3a40c463a196c29bf7ba" },
        { "Skein-512-128", "7c9aff5c3738e3faadc7a5265768def1" },
        { "Skein-512-160", "49daf1ccebb3544bc93cb5019ba91b0eea8876ee" },
        { "Skein-512-224", "1541ae9fc3ebe24eb758ccb1fd60c2c31a9ebfe65b220086e7819e25" },
        { "Skein-512-256", "39ccc4554a8b31853b9de7a1fe638a24cce6b35a55f2431009e18780335d2621" },
        { "Skein-512-384", "dd5aaf4589dc227bd1eb7bc68771f5baeaa3586ef6c7680167a023ec8ce26980f06c4082c488b4ac9ef313f8cbe70808" },
        { "Skein-512-512", "bc5b4c50925519c290cc634277ae3d6257212395cba733bbad37a4af0fa06af41fca7903d06564fea7a2d3730dbdb80c1f85562dfcc070334ea4d1d9e72cba7a" },
        { "Skein-1024-384", "1fdb081963b960e89eaa11b87dda55e8a55a3e1066b30e38d8ae2a45242f7dadfaf06d80ca8a73cd8242ce5eab84c164" },
        { "Skein-1024-512", "e2943eb0bc0efabd49503a76edf7cfcf072db25bad94ed44fe537284163f3119c47ac6f78699b4272255966e0aba65c75a0a64bd23df6996d1bc3174afd9fa8b" },
        { "Skein-1024-1024", "0fff9563bb3279289227ac77d319b6fff8d7e9f09da1247b72a0a265cd6d2a62645ad547ed8193db48cff847c06494a03f55666d3b47eb4c20456c9373c86297d630d5578ebd34cb40991578f9f52b18003efa35d3da6553ff35db91b81ab890bec1b189b7f52cb2a783ebb7d823d725b0b4a71f6824e88f68f982eefc6d19c6" },
    };

    static private byte[] shortMsg = Hex.decode("fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
            + "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb"
            + "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a"
            + "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410");

    static private String[][] shortVectors =
    {
        { "Skein-256-128", "9703382ea27dc2913e9d02cd976c582f" },
        { "Skein-256-160", "0cd491b7715704c3a15a45a1ca8d93f8f646d3a1" },
        { "Skein-256-224", "afd1e2d0f5b6cd4e1f8b3935fa2497d27ee97e72060adac099543487" },
        { "Skein-256-256", "4de6fe2bfdaa3717a4261030ef0e044ced9225d066354610842a24a3eafd1dcf" },
        { "Skein-512-128", "c901b1c04af3da4dce05d7975c419224" },
        { "Skein-512-160", "ef03079d61b57c6047e15fa2b35b46fa24279539" },
        { "Skein-512-224", "d9e3219b214e15246a2038f76a573e018ef69b385b3bd0576b558231" },
        { "Skein-512-256", "809dd3f763a11af90912bbb92bc0d94361cbadab10142992000c88b4ceb88648" },
        { "Skein-512-384", "825f5cbd5da8807a7b4d3e7bd9cd089ca3a256bcc064cd73a9355bf3ae67f2bf93ac7074b3b19907a0665ba3a878b262" },
        { "Skein-512-512", "1a0d5abf4432e7c612d658f8dcfa35b0d1ab68b8d6bd4dd115c23cc57b5c5bcdde9bff0ece4208596e499f211bc07594d0cb6f3c12b0e110174b2a9b4b2cb6a9" },
        { "Skein-1024-384", "9c3d0648c11f31c18395d5e6c8ebd73f43d189843fc45235e2c35e345e12d62bc21a41f65896ddc6a04969654c2e2ce9" },
        { "Skein-1024-512", "5d0416f49c2d08dfd40a1446169dc6a1d516e23b8b853be4933513051de8d5c26baccffb08d3b16516ba3c6ccf3e9a6c78fff6ef955f2dbc56e1459a7cdba9a5" },
        { "Skein-1024-1024", "96ca81f586c825d0360aef5acaec49ad55289e1797072eee198b64f349ce65b6e6ed804fe38f05135fe769cc56240ddda5098f620865ce4a4278c77fa2ec6bc31c0f354ca78c7ca81665bfcc5dc54258c3b8310ed421d9157f36c093814d9b25103d83e0ddd89c52d0050e13a64c6140e6388431961685734b1f138fe2243086" },
    };
    
    static private String[][] shortMacVectors = 
    {
        { "Skein-Mac-256-128", "738f8b23541d50f691ab60af664c1583" },
        { "Skein-Mac-256-160", "fe07fe50f99b7683bc16980041d8c045857f1189" },
        { "Skein-Mac-256-224", "0bc19b185f5bfe50f0dba7ab49cd8ca9440260edd5a392d4bdcd2216" },
        { "Skein-Mac-256-256", "9837ba53d23afcdabd9fcd614ce9e51c0ebecec7a210df4d3724ed591f026ef1" },
        { "Skein-Mac-512-128", "6d34f46f2033947da7a9dfb068f4102d" },
        { "Skein-Mac-512-160", "83cb2effecaa60674c2f9fb2fb6771a9899708ba" },
        { "Skein-Mac-512-224", "e5f83c032875451f31977cd649c866708cb283a509e99cdfd4d995c5" },
        { "Skein-Mac-512-256", "ed5507ec551ec944c6ed531990c32907eca885dd3af3d50dd09f1dbef422bb11" },
        { "Skein-Mac-512-384", "b8f84a212723b92a591d6dc145c1655c70df710e9f3365064abdf79e9288dced2f0f895d81f465c811f1207b43b8cfce" },
        { "Skein-Mac-512-512", "d13ba582467096a0f862114d97baa218512f39c82c984aa29deee724950d7f0929f726173dd42bc35566b0dbfbf5d2a1552ba6f132de301846714215b64e7f82" },
        { "Skein-Mac-1024-384", "490dbbd049403e602ee3535181a70ee2eb5ade6d83b519953dd0d93c45729f098b679efcd64b5e3f03cd2fa9f1e70d69" },
        { "Skein-Mac-1024-512", "ce7f1052fa486309d73058d1d4986f886d966a849c72d196bb2b97fc9fb0b1e69f43a521ebd979f5a5581bd12a0dbd0d1ee27af0929881f1d35c875cc0542ecf" },
        { "Skein-Mac-1024-1024", "60cd8c755b331bcefe97be5a9fe6f63146d12520ca7b20dbc5c5370dae2ff9815c95fab564329a01eced76f0ecb1944ad52a74e89fa1b6cdcdcee4c71c2c18909c4d1324d279fac5ca2280eea0fa70521cf4ea8c616a3ac6082c2244bec5c1ab3a173faf29d84bec7fb852e278ed57785535c979b33b81465c437cd998c04b95" },
    };

    static private String[][] shortHMacVectors = 
        {
        { "HMAC-Skein-256-128", "926a445d5218605286dfe0542a437012" },
        { "HMAC-Skein-256-160", "5ebc30295e4562a879f94db531ada465073b8bb7" },
        { "HMAC-Skein-256-224", "a05b3cfc6b86fda7f5dcf0afbb707dc745fa55279a3f80e2c9977ff1" },
        { "HMAC-Skein-256-256", "51741f6e8ebf133216ac8e05c7a75a6339351fd2dcc4db04e418521c628a2111" },
        { "HMAC-Skein-512-128", "ad51f8c7b1b347fe52f0f5c71ae9b8eb" },
        { "HMAC-Skein-512-160", "e0d06c2d406f32bb14dbb2129176219b62d4f89f" },
        { "HMAC-Skein-512-224", "e7e5327e2aaa88d0038049e8112db31df223be4c31da24abf03731a8" },
        { "HMAC-Skein-512-256", "30177414f6e35019cacc2e3ae474b25765e6e0e541e16d754c3dad19df763ab0" },
        { "HMAC-Skein-512-384", "7f0ba3c1c642cf09eb03d0e3760fe172f22fb263006b1fba5bdea1bfaf6e971c17e039abb0030d1a40ac94a747732cce" },
        { "HMAC-Skein-512-512", "70d864e7f6cbd446778914a951d1961e646ee17a3da8eae551d29f4fafc540b0457cc9f8064c511b80dc29f8369fb5dc258559542abb5342c4892f22934bf5f1" },
        { "HMAC-Skein-1024-384", "e7d3465b30b5089e24244e747a91f7cb255596b49843466497c07e120c5c2232f51151b185a1e8a5610f041a85cc59ee" },
        { "HMAC-Skein-1024-512", "c428059ae2d17ba13e461384c4a64cb0be694909e7a04e4983a4fc16476d644c7764e0019b33ea2a8719f731a579f4f7015da7ec1bc56a4920071ac41da836fe" },
        { "HMAC-Skein-1024-1024", "3ebd13ec7bf1533c343ac78e1b5146225ce7629787f3997b646139c1b80d6f54cd562b7625419ede8710d76410dfb8617514ca3f7abf17657d2bc96722071adb2a6ecd9795a1ef5e4734b450d588efcbc3220faf53c880e61438bb953e024e48db6a745d2368375ac792be858cd01915e28590d4d6d599be95f6e6ceed7d7d91" },
        };
    
    static private byte[] shortMacMessage = Hex.decode("d3090c72167517f7");
    static private byte[] shortMacKey = Hex.decode("cb41f1706cde09651203c2d0efbaddf8");

    static private byte[] keyIdentifier = "asecretkey".getBytes();
    static private byte[] keyIdentifierVector = Hex.decode("ca9970a83997e1c346c4348b54cfc9ba7e19bfba");

    public String getName()
    {
        return "Skein";
    }

    void test(String type, String algorithm, byte[] message, String expected) throws Exception
    {
        MessageDigest digest = MessageDigest.getInstance(algorithm, provider);

        byte[] result = digest.digest(message);
        byte[] result2 = digest.digest(message);

        // test zero results valid
        if (!MessageDigest.isEqual(result, Hex.decode(expected)))
        {
            fail(type + " result not equal for " + algorithm, expected, new String(Hex.encode(result)));
        }

        // test one digest the same message with the same instance
        if (!MessageDigest.isEqual(result, result2))
        {
            fail(type + " result object 1 not equal");
        }

        if (!MessageDigest.isEqual(result, Hex.decode(expected)))
        {
            fail(type + " result object 1 not equal");
        }

        // test two, single byte updates
        for (int i = 0; i < message.length; i++)
        {
            digest.update(message[i]);
        }
        result2 = digest.digest();

        if (!MessageDigest.isEqual(result, result2))
        {
            fail(type + " result object 2 not equal");
        }

        // test three, two half updates
        digest.update(message, 0, message.length / 2);
        digest.update(message, message.length / 2, message.length - message.length / 2);
        result2 = digest.digest();

        if (!MessageDigest.isEqual(result, result2))
        {
            fail(type + " result object 3 not equal");
        }

        // test four, clone test
        digest.update(message, 0, message.length / 2);
        MessageDigest d = (MessageDigest)digest.clone();
        digest.update(message, message.length / 2, message.length - message.length / 2);
        result2 = digest.digest();

        if (!MessageDigest.isEqual(result, result2))
        {
            fail(type + " result object 4(a) not equal");
        }

        d.update(message, message.length / 2, message.length - message.length / 2);
        result2 = d.digest();

        if (!MessageDigest.isEqual(result, result2))
        {
            fail(type + " result object 4(b) not equal");
        }

        // test five, check reset() method
        digest.update(message, 0, message.length / 2);
        digest.reset();
        digest.update(message, 0, message.length / 2);
        digest.update(message, message.length / 2, message.length - message.length / 2);
        result2 = digest.digest();

        if (!MessageDigest.isEqual(result, result2))
        {
            fail(type + " result object 5 not equal");
        }
    }

    private void testMac(String algorithm, byte[] message, byte[] key, String expected) throws Exception
    {
        Mac mac = Mac.getInstance(algorithm, provider);

        mac.init(new SecretKeySpec(key, algorithm));

        byte[] result = mac.doFinal(message);
        byte[] result2 = mac.doFinal(message);

        // test zero results valid
        if (!MessageDigest.isEqual(result, Hex.decode(expected)))
        {
            fail("null result not equal for " + algorithm, expected, new String(Hex.encode(result)));
        }

        // test one digest the same message with the same instance
        if (!MessageDigest.isEqual(result, result2))
        {
            fail("Result object 1 not equal");
        }

        if (!MessageDigest.isEqual(result, Hex.decode(expected)))
        {
            fail("Result object 1 not equal");
        }

        // test two, single byte updates
        for (int i = 0; i < message.length; i++)
        {
            mac.update(message[i]);
        }
        result2 = mac.doFinal();

        if (!MessageDigest.isEqual(result, result2))
        {
            fail("Result object 2 not equal");
        }

        // test three, two half updates
        mac.update(message, 0, message.length / 2);
        mac.update(message, message.length / 2, message.length - message.length / 2);
        result2 = mac.doFinal();

        if (!MessageDigest.isEqual(result, result2))
        {
            fail("Result object 3 not equal");
        }

        // test five, check reset() method
        mac.update(message, 0, message.length / 2);
        mac.reset();
        mac.update(message, 0, message.length / 2);
        mac.update(message, message.length / 2, message.length - message.length / 2);
        result2 = mac.doFinal();

        if (!MessageDigest.isEqual(result, result2))
        {
            fail("Result object 5 not equal");
        }

        // test six, check KeyGenerator
        KeyGenerator generator = KeyGenerator.getInstance(algorithm, provider);

        mac = Mac.getInstance(algorithm, provider);
        final SecretKey generatedKey = generator.generateKey();
        if (generatedKey.getEncoded().length != mac.getMacLength())
        {
            fail("Default mac key length for " + algorithm);
        }
        mac.init(generatedKey);
        mac.update(message);
        mac.doFinal();
    }

    private void testParameters() throws Exception
    {
        Mac mac = Mac.getInstance("Skein-Mac-512-160", provider);

        // test six, init using SkeinParameters
        mac.init(new SecretKeySpec(shortMacKey, "Skein-Mac-512-160"),
                new SkeinParameterSpec.Builder().setKeyIdentifier(keyIdentifier).build());
        byte[] result = mac.doFinal(shortMacMessage);

        if (!MessageDigest.isEqual(result, keyIdentifierVector))
        {
            fail("Mac with key identifier failed.", new String(Hex.encode(keyIdentifierVector)),  new String(Hex.encode(result)));
        }
    }

    private void testMacKeyGenerators(String algorithm) throws Exception
    {
        KeyGenerator gen = KeyGenerator.getInstance(algorithm);
        
        int outputSize = Integer.parseInt(algorithm.substring(algorithm.lastIndexOf('-') + 1));
        SecretKey key = gen.generateKey();
        
        if (key.getEncoded().length != (outputSize / 8)) {
            fail(algorithm + " key length should be equal to output size " + (outputSize) + ", but was " + key.getEncoded().length * 8);
        }
    }

    public void performTest() throws Exception
    {
        for (int i = 0; i < nullVectors.length; i++)
        {
            test("Null message", nullVectors[i][0], nullMsg, nullVectors[i][1]);
        }
        for (int i = 0; i < shortVectors.length; i++)
        {
            test("Short message", shortVectors[i][0], shortMsg, shortVectors[i][1]);
        }
        for (int i = 0; i < shortMacVectors.length; i++)
        {
            testMac(shortMacVectors[i][0], shortMacMessage, shortMacKey, shortMacVectors[i][1]);
            testMacKeyGenerators(shortMacVectors[i][0]);
        }

        for (int i = 0; i < shortHMacVectors.length; i++)
        {
            testMac(shortHMacVectors[i][0], shortMacMessage, shortMacKey, shortHMacVectors[i][1]);
            testMacKeyGenerators(shortHMacVectors[i][0]);
        }
        testParameters();
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new SkeinTest());
    }
}
