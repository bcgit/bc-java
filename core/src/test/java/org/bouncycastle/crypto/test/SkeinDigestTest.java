package org.bouncycastle.crypto.test;

import java.io.IOException;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SkeinDigest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class SkeinDigestTest
    extends SimpleTest
{
    private static class Case
    {
        private byte[] message;
        private byte[] digest;
        private int blockSize;
        private int outputSize;

        public Case(int blockSize, int outputSize, String message, String digest)
        {
            this.blockSize = blockSize;
            this.outputSize = outputSize;
            this.message = Hex.decode(message);
            this.digest = Hex.decode(digest);
        }

        public int getOutputSize()
        {
            return outputSize;
        }

        public int getBlockSize()
        {
            return blockSize;
        }

        public byte[] getMessage()
        {
            return message;
        }

        public byte[] getDigest()
        {
            return digest;
        }

    }

    // Test cases from skein_golden_kat.txt and skein_golden_kat_short.txt in Skein 1.3 NIST CD
    private static final Case[] TEST_CASES = {
        new Case(256, 256, "", "c8877087da56e072870daa843f176e9453115929094c3a40c463a196c29bf7ba"),
        new Case(256, 256, "fb", "088eb23cc2bccfb8171aa64e966d4af937325167dfcd170700ffd21f8a4cbdac"),
        new Case(256, 256, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8",
            "5c3002ff57a627089ea2f97a5000d5678416389019e80e45a3bbcab118315d26"),
        new Case(256, 256, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
            + "78bb393a1a5f79bef30995a85a129233",
            "640c894a4bba6574c83e920ddf7dd2982fc634881bbbcb9d774eae0a285e89ce"),
        new Case(256, 160, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
            + "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb"
            + "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a"
            + "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
            "0cd491b7715704c3a15a45a1ca8d93f8f646d3a1"),
        new Case(256, 224, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
            + "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb"
            + "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a"
            + "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
            "afd1e2d0f5b6cd4e1f8b3935fa2497d27ee97e72060adac099543487"),
        new Case(256, 256, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
            + "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb"
            + "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a"
            + "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
            "4de6fe2bfdaa3717a4261030ef0e044ced9225d066354610842a24a3eafd1dcf"),
        new Case(256, 384, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
            + "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb"
            + "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a"
            + "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
            "954620fb31e8b782a2794c6542827026fe069d715df04261629fcbe81d7d529b"
                + "95ba021fa4239fb00afaa75f5fd8e78b"),
        new Case(256, 512, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
            + "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb"
            + "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a"
            + "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
            "51347e27c7eabba514959f899a6715ef6ad5cf01c23170590e6a8af399470bf9"
                + "0ea7409960a708c1dbaa90e86389df254abc763639bb8cdf7fb663b29d9557c3"),
        new Case(256, 1024, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
            + "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb"
            + "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a"
            + "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
            "6c9b6facbaf116b538aa655e0be0168084aa9f1be445f7e06714585e5999a6c9"
                + "84fffa9d41a316028692d4aad18f573fbf27cf78e84de26da1928382b023987d"
                + "cfe002b6201ea33713c54a8a5d9eb346f0365e04330d2faaf7bc8aba92a5d7fb"
                + "6345c6fb26750bce65ab2045c233627679ac6e9acb33602e26fe3526063ecc8b"),

        new Case(512, 512, "", "bc5b4c50925519c290cc634277ae3d6257212395cba733bbad37a4af0fa06af4"
            + "1fca7903d06564fea7a2d3730dbdb80c1f85562dfcc070334ea4d1d9e72cba7a"),
        new Case(512, 512, "fb", "c49e03d50b4b2cc46bd3b7ef7014c8a45b016399fd1714467b7596c86de98240"
            + "e35bf7f9772b7d65465cd4cffab14e6bc154c54fc67b8bc340abf08eff572b9e"),
        new Case(512, 512, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8",
            "abefb179d52f68f86941acbbe014cc67ec66ad78b7ba9508eb1400ee2cbdb06f"
                + "9fe7c2a260a0272d0d80e8ef5e8737c0c6a5f1c02ceb00fb2746f664b85fcef5"),
        new Case(512, 512, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
            + "78bb393a1a5f79bef30995a85a129233",
            "5c5b7956f9d973c0989aa40a71aa9c48a65af2757590e9a758343c7e23ea2df4"
                + "057ce0b49f9514987feff97f648e1dd065926e2c371a0211ca977c213f14149f"),
        new Case(512, 160, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
            + "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb"
            + "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a"
            + "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
            "ef03079d61b57c6047e15fa2b35b46fa24279539"),
        new Case(512, 224, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
            + "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb"
            + "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a"
            + "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
            "d9e3219b214e15246a2038f76a573e018ef69b385b3bd0576b558231"),
        new Case(512, 256, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
            + "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb"
            + "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a"
            + "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
            "809dd3f763a11af90912bbb92bc0d94361cbadab10142992000c88b4ceb88648"),
        new Case(512, 384, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
            + "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb"
            + "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a"
            + "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
            "825f5cbd5da8807a7b4d3e7bd9cd089ca3a256bcc064cd73a9355bf3ae67f2bf"
                + "93ac7074b3b19907a0665ba3a878b262"),
        new Case(512, 512, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
            + "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb"
            + "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a"
            + "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
            "1a0d5abf4432e7c612d658f8dcfa35b0d1ab68b8d6bd4dd115c23cc57b5c5bcd"
                + "de9bff0ece4208596e499f211bc07594d0cb6f3c12b0e110174b2a9b4b2cb6a9"),

        new Case(1024, 1024, "", "0fff9563bb3279289227ac77d319b6fff8d7e9f09da1247b72a0a265cd6d2a62"
            + "645ad547ed8193db48cff847c06494a03f55666d3b47eb4c20456c9373c86297"
            + "d630d5578ebd34cb40991578f9f52b18003efa35d3da6553ff35db91b81ab890"
            + "bec1b189b7f52cb2a783ebb7d823d725b0b4a71f6824e88f68f982eefc6d19c6"),
        new Case(1024, 1024, "fb", "6426bdc57b2771a6ef1b0dd39f8096a9a07554565743ac3de851d28258fcff22"
            + "9993e11c4e6bebc8b6ecb0ad1b140276081aa390ec3875960336119427827473"
            + "4770671b79f076771e2cfdaaf5adc9b10cbae43d8e6cd2b1c1f5d6c82dc96618"
            + "00ddc476f25865b8748253173187d81da971c027d91d32fb390301c2110d2db2"),
        new Case(1024, 1024, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8",
            "140e93726ab0b0467c0b8a834ad8cda4d1769d273661902b70db0dcb5ee692ac"
                + "b3f852d03b11f857850f2428432811309c1dcbe5724f00267ea3667e89fadb4e"
                + "4911da6b0ba8a7eddf87c1c67152ef0f07b7fead3557318478bdef5ad1e5926d"
                + "7071fdd4bfa5076d4b3253f8de479ebdf5357676f1641b2f097e9b785e9e528e"),
        new Case(1024, 1024, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
            + "78bb393a1a5f79bef30995a85a129233",
            "31105e1ef042c30b95b16e0f6e6a1a19172bb7d54a0597dd0c711194888efe1d"
                + "bce82d47416df9577ca387219f06e45cd10964ff36f6711edbbea0e9595b0f66"
                + "f72b755d70a46857e0aec98561a743d49370d8e572e212811273125f66cc30bf"
                + "117d3221894c48012bf6e2219de91e064b01523517420a1e00f71c4cc04bab62"),
        new Case(1024, 160, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
            + "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb"
            + "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a"
            + "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
            "2e6a4cbf2ef05ea9c24b93e8d1de732ddf2739eb"),
        new Case(1024, 224, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
            + "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb"
            + "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a"
            + "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
            "1d6de19f37f7a3c265440eecb4b9fbd3300bb5ac60895cfc0d4d3c72"),
        new Case(1024, 256, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
            + "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb"
            + "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a"
            + "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
            "986a4d472b123e8148731a8eac9db23325f0058c4ccbc44a5bb6fe3a8db672d7"),
        new Case(1024, 384, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
            + "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb"
            + "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a"
            + "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
            "9c3d0648c11f31c18395d5e6c8ebd73f43d189843fc45235e2c35e345e12d62b"
                + "c21a41f65896ddc6a04969654c2e2ce9"),
        new Case(1024, 512, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
            + "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb"
            + "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a"
            + "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
            "5d0416f49c2d08dfd40a1446169dc6a1d516e23b8b853be4933513051de8d5c2"
                + "6baccffb08d3b16516ba3c6ccf3e9a6c78fff6ef955f2dbc56e1459a7cdba9a5"),
        new Case(1024, 1024, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
            + "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb"
            + "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a"
            + "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
            "96ca81f586c825d0360aef5acaec49ad55289e1797072eee198b64f349ce65b6"
                + "e6ed804fe38f05135fe769cc56240ddda5098f620865ce4a4278c77fa2ec6bc3"
                + "1c0f354ca78c7ca81665bfcc5dc54258c3b8310ed421d9157f36c093814d9b25"
                + "103d83e0ddd89c52d0050e13a64c6140e6388431961685734b1f138fe2243086"),

    };

    public String getName()
    {
        return "SkeinDigest";
    }

    public void performTest()
        throws Exception
    {
        runTest(TEST_CASES[7]);
        for (int i = 0; i < TEST_CASES.length; i++)
        {
            Case test = TEST_CASES[i];
            runTest(test);
        }
    }

    private void runTest(Case dc)
    {
        SkeinDigest digest = new SkeinDigest(dc.getBlockSize(), dc.getOutputSize());

        byte[] message = dc.getMessage();
        digest.update(message, 0, message.length);

        byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);

        if (!Arrays.areEqual(output, dc.getDigest()))
        {
            fail(digest.getAlgorithmName() + " message mismatch.\n Message " + new String(Hex.encode(dc.getMessage())),
                new String(Hex.encode(dc.getDigest())), new String(Hex.encode(output)));
        }

        // Clone test
        digest.update(message, 0, message.length / 2);

        // clone the Digest
        Digest d = new SkeinDigest(digest);

        digest.update(message, message.length / 2, message.length - message.length / 2);
        digest.doFinal(output, 0);

        if (!areEqual(dc.getDigest(), output))
        {
            fail("failing clone vector test", new String(Hex.encode(dc.getDigest())), new String(Hex.encode(output)));
        }

        d.update(message, message.length / 2, message.length - message.length / 2);
        d.doFinal(output, 0);

        if (!areEqual(dc.getDigest(), output))
        {
            fail("failing second clone vector test", new String(Hex.encode(dc.getDigest())), new String(Hex.encode(output)));
        }

        //
        // memo test
        //
        Memoable m = (Memoable)digest;

        digest.update(message, 0, message.length / 2);

        // copy the Digest
        Memoable copy1 = m.copy();
        Memoable copy2 = copy1.copy();

        digest.update(message, message.length / 2, message.length - message.length / 2);
        digest.doFinal(output, 0);

        if (!areEqual(dc.getDigest(), output))
        {
            fail("failing memo vector test", new String(Hex.encode(dc.getDigest())), new String(Hex.encode(output)));
        }

        m.reset(copy1);

        digest.update(message, message.length / 2, message.length - message.length / 2);
        digest.doFinal(output, 0);

        if (!areEqual(dc.getDigest(), output))
        {
            fail("failing memo reset vector test", new String(Hex.encode(dc.getDigest())), new String(Hex.encode(output)));
        }

        Digest md = (Digest)copy2;

        md.update(message, message.length / 2, message.length - message.length / 2);
        md.doFinal(output, 0);

        if (!areEqual(dc.getDigest(), output))
        {
            fail("failing memo copy vector test", new String(Hex.encode(dc.getDigest())), new String(Hex.encode(output)));
        }
    }

    public static void main(String[] args)
        throws IOException
    {
        // generateTests();
        runTest(new SkeinDigestTest());
    }

}
