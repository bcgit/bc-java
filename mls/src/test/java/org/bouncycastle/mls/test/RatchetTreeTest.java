package org.bouncycastle.mls.test;

import junit.framework.TestCase;
import org.bouncycastle.mls.*;
import org.bouncycastle.mls.crypto.CipherSuite;
import org.bouncycastle.mls.crypto.Secret;
import org.bouncycastle.mls.protocol.PreSharedKeyID;
import org.bouncycastle.mls.protocol.ResumptionPSKUsage;
import org.bouncycastle.util.encoders.Hex;
import sun.reflect.generics.tree.Tree;

import java.nio.charset.StandardCharsets;
import java.security.InvalidParameterException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class RatchetTreeTest
        extends TestCase
{


    public void testFigure10()
        throws Exception
    {
        // psks

        KeyScheduleEpoch.PSKWithSecret externalPSK = new KeyScheduleEpoch.PSKWithSecret(
                PreSharedKeyID.external(
                        Hex.decode("00010203"),
                        Hex.decode("04050607")
                ),
                new Secret("an externally provisioned PSK".getBytes())
        );

        KeyScheduleEpoch.PSKWithSecret resumptionPSK = new KeyScheduleEpoch.PSKWithSecret(
                PreSharedKeyID.resumption(
                        ResumptionPSKUsage.APPLICATION,
                        Hex.decode("10111213"),
                        0xa0a0a0a0a0a0a0a0L,
                        Hex.decode("14151617")),
                new Secret("a resumption PSK".getBytes())
        );

        List<KeyScheduleEpoch.PSKWithSecret> psks = Arrays.asList(externalPSK, resumptionPSK);


        /*
                  W = root
               /            \
              _=U             Y
            /   \          /     \
          T     _=V      X       _=Z
         / \    / \     / \     / \
         A  B   _  _    E  F   G  _=H
         0  1   2  3    4  5   6  7
         */


        CipherSuite suite = new CipherSuite(CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);
        // A creates a group with B, ..., G

        // A creates a group
        int newMembers = 6;
        KeyScheduleEpoch[] epochs = new  KeyScheduleEpoch[newMembers + 1];

        epochs[0] = KeyScheduleEpoch.forCreator(suite);

        // A adds B, ..., G via Welcome
        //Todo have these in a ratchet tree
        Secret[] commitSecrets = new Secret[newMembers];
        byte[][] contexts = new byte[newMembers][];
        TreeSize treeSize; //TODO replace or make treeSize iterable or make into a list?

        KeyScheduleEpoch.JoinSecrets adderJoin;
        KeyScheduleEpoch.JoinSecrets joinerJoin;
        for (int i = 0; i < newMembers; i++)
        {
            char memberID =(char)('B' + i);
            System.out.println("A is adding " + memberID);
            commitSecrets[i] = new Secret(("commit secret is'commitsecret" + (i+1) + "'").getBytes(StandardCharsets.UTF_8));
            contexts[i] = ("context" + (i+1)).getBytes(StandardCharsets.UTF_8);
            treeSize = TreeSize.forLeaves(i + 2);

            // (A adds everyone in this case)
            adderJoin = epochs[0].startCommit(commitSecrets[i], psks, contexts[i]);
            joinerJoin = new KeyScheduleEpoch.JoinSecrets(suite, adderJoin.joinerSecret, psks);

            // Complete for adder and joiner (update epoches)
            epochs[0] = adderJoin.complete(treeSize, contexts[i]);
            epochs[i+1] = joinerJoin.complete(treeSize, contexts[i]);

            // Next for other members
            for (int j = 0; j < i; j++)
            {
                epochs[j+1] = epochs[j+1].next(treeSize, null, commitSecrets[i], psks, contexts[i]);
            }

            // Assert check all member after adding
            for (int x = 0; x < i + 2; x++)
            {
                for (int y = x + 1; y < i + 2; y++)
                {
                    assertEquals(epochs[x], epochs[y]);
                }
            }
        }

        // F sends an empty Commit, setting X, Y, W

//        Secret commitSecret = new Secret(("this is F's empty commit secret").getBytes(StandardCharsets.UTF_8));
//        epochs[5].next(treeSize, null, commitSecret,  psks, null);



        // G removes C and D, blanking V, U, and setting Y, W

        // B sends an empty Commit, setting T and W


    }

    private void printGivenLevel(NodeIndex root, int level, long depth, long height)
    {
        if (root == null)
            return;


        if (level == 1)
        {
            System.out.print(root.value() + String.format("%"+((2<<(height-depth+2))-1)+"s", ""));
        }
        else if (level > 1) {
            printGivenLevel(root.left(), level - 1, depth, height);
            printGivenLevel(root.right(), level - 1, depth, height);
        }
    }

    private void printTree(TreeSize size)
    {
        NodeIndex root = new NodeIndex(size.leafCount() - 1);
        for (int i = 1; i <= size.depth() + 1; i++)
        {
            System.out.printf("%"+((2<<(size.depth()-i+1))-1)+"s", "");
            printGivenLevel(root, i, i, size.depth());
            System.out.println();
        }
    }
    public void testPrintTree()
    {
        TreeSize size = TreeSize.forLeaves(8);
//        System.out.println(size.depth());
        printTree(size);

    }

    public void testRatchetTree()
            throws Exception
    {
        CipherSuite suite = new CipherSuite(CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);
        TreeSize treeSize = TreeSize.forLeaves(8);

        byte[] encryptionSecretData = Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        Secret encryptionSecret = new Secret(encryptionSecretData);
        GroupKeySet keys = new GroupKeySet(suite, treeSize, encryptionSecret);

        for (int i = 0; i < treeSize.leafCount(); i++)
        {
            LeafIndex leaf = new LeafIndex(i);
        }

    }
    public void testTreee() throws Exception
    {
        // psks

        KeyScheduleEpoch.PSKWithSecret externalPSK = new KeyScheduleEpoch.PSKWithSecret(
                PreSharedKeyID.external(
                        Hex.decode("00010203"),
                        Hex.decode("04050607")
                ),
                new Secret("an externally provisioned PSK".getBytes())
        );

        KeyScheduleEpoch.PSKWithSecret resumptionPSK = new KeyScheduleEpoch.PSKWithSecret(
                PreSharedKeyID.resumption(
                        ResumptionPSKUsage.APPLICATION,
                        Hex.decode("10111213"),
                        0xa0a0a0a0a0a0a0a0L,
                        Hex.decode("14151617")),
                new Secret("a resumption PSK".getBytes())
        );

        List<KeyScheduleEpoch.PSKWithSecret> psks = Arrays.asList(externalPSK, resumptionPSK);
        CipherSuite suite = new CipherSuite(CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);
        // A creates a group with B, ..., G
        byte[] encryptionSecretData = Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        Secret encryptionSecret = new Secret(encryptionSecretData);

        TreeSize treeSize = TreeSize.forLeaves(1);
        GroupKeySet keys = new GroupKeySet(suite, treeSize, encryptionSecret);



    }

    public void testRatchets() throws Exception {
        long generations = 10;
        CipherSuite suite = new CipherSuite(CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);

        TreeSize treeSize = TreeSize.forLeaves(8);
        int expectedKeySize = suite.getAEAD().getKeySize();
        int expectedNonceSize = suite.getAEAD().getNonceSize();

        byte[] encryptionSecretData = Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        Secret encryptionSecret = new Secret(encryptionSecretData);
        GroupKeySet keys = new GroupKeySet(suite, treeSize, encryptionSecret);

        Map<NodeIndex, Secret> secrets = keys.secretTree.secrets;

        // Verify next()
        for (long i = 0; i < treeSize.leafCount(); i++)
        {
            LeafIndex leaf = new LeafIndex(i);
            for (int generation = 0; generation < generations; generation++)
            {
                // TODO verify that the generated values are correct
                KeyGeneration hsGen = keys.handshakeRatchet(leaf).next();
                assertEquals(hsGen.generation, generation);
                assertEquals(hsGen.key.length, expectedKeySize);
                assertEquals(hsGen.nonce.length, expectedNonceSize);

                // TODO verify that the generated values are correct
                KeyGeneration appGen = keys.applicationRatchet(leaf).next();
                assertEquals(appGen.generation, generation);
                assertEquals(appGen.key.length, expectedKeySize);
                assertEquals(appGen.nonce.length, expectedNonceSize);

            }
        }

        // Verify get()
        LeafIndex leaf = new LeafIndex(0);
        KeyGeneration hsGen1 = keys.handshakeRatchet(leaf).next();
        int generation = hsGen1.generation;
        KeyGeneration hsGen2 = keys.handshakeRatchet(leaf).get(generation);
        assertEquals(hsGen1, hsGen2);

        // Verify erase()
        keys.handshakeRatchet(leaf).erase(generation);
        try {
            keys.handshakeRatchet(leaf).get(generation);
            fail("Ratchet failed to erase");
        } catch (InvalidParameterException e) {
            // Thrown as expected
        }
    }
}
