package org.bouncycastle.mls.test;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.mls.KeyScheduleEpoch;
import org.bouncycastle.mls.TreeKEM.LeafIndex;
import org.bouncycastle.mls.TreeKEM.LeafNode;
import org.bouncycastle.mls.TreeKEM.NodeIndex;
import org.bouncycastle.mls.TreeKEM.TreeKEMPublicKey;
import org.bouncycastle.mls.client.Group;
import org.bouncycastle.mls.codec.AuthenticatedContent;
import org.bouncycastle.mls.codec.KeyPackage;
import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSMessage;
import org.bouncycastle.mls.codec.PreSharedKeyID;
import org.bouncycastle.mls.crypto.CipherSuite;
import org.bouncycastle.mls.crypto.Secret;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.Queue;
import java.util.Stack;

public class ClientVectorTest
        extends TestCase
{

    public void testPassiveClientWelcome() throws Exception
    {
        runPassiveClientTest("passive-client-welcome.txt");
    }
    public void testPassiveClientRandom() throws Exception
    {
        runPassiveClientTest("passive-client-random.txt");
    }
    public void testPassiveClientHandlingCommit() throws Exception
    {
        runPassiveClientTest("passive-client-handling-commit.txt");
    }

    private void runPassiveClientTest(String filename)
            throws Exception
    {
        InputStream src = VectorTest.class.getResourceAsStream(filename);
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line;
        HashMap<String, String> buf = new HashMap<>();
        Stack<String> readingStack = new Stack<>();
        int count = 0;

        ArrayList<PreSharedKeyID> externalPSKs = new ArrayList<>();
        List<byte[]> proposals = new ArrayList<>();
        class Epoch
        {
            List<byte[]> proposals;
            byte[] commit;
            byte[] epoch_authenticator;

            public Epoch(List<byte[]> proposals, byte[] commit, byte[] epoch_authenticator)
            {
                this.proposals = new ArrayList<>(proposals);
                this.commit = commit;
                this.epoch_authenticator = epoch_authenticator;
            }
        }
        List<Epoch> epochs = new ArrayList<>();


        while((line = bin.readLine())!= null)
        {
            line = line.trim();
            if (line.endsWith("START"))
            {
                readingStack.push(line.substring(0, line.indexOf("START")));
                continue;
            }
            if(line.endsWith("STOP"))
            {
                readingStack.pop();
                continue;
            }
            if (line.length() == 0)
            {
                if (buf.size() > 0)
                {
                    try
                    {
                        System.out.print("test case: " + count);
                        short cipherSuite = Short.parseShort(buf.get("cipher_suite"));
                        byte[] key_package = Hex.decode(buf.get("key_package"));
                        byte[] signature_priv = Hex.decode(buf.get("signature_priv"));
                        byte[] encryption_priv = Hex.decode(buf.get("encryption_priv"));
                        byte[] init_priv = Hex.decode(buf.get("init_priv"));
                        byte[] welcome = Hex.decode(buf.get("welcome"));
                        byte[] initial_epoch_authenticator = Hex.decode(buf.get("initial_epoch_authenticator"));
                        byte[] ratchet_tree;
                        TreeKEMPublicKey tree = null;
                        if (buf.get("ratchet_tree").equals("None"))
                        {
                            ratchet_tree = new byte[0];
                        }
                        else
                        {
                            ratchet_tree = Hex.decode(buf.get("ratchet_tree"));
                            tree = (TreeKEMPublicKey) MLSInputStream.decode(ratchet_tree, TreeKEMPublicKey.class);
                        }

                        CipherSuite suite = new CipherSuite(cipherSuite);
                        AsymmetricCipherKeyPair leafKeyPair = suite.getHPKE().deserializePrivateKey(encryption_priv, null);
                        Map<Secret, byte[]> externalPsks = new HashMap<>();
                        for (PreSharedKeyID ext : externalPSKs)
                        {
                            externalPsks.put(ext.external.externalPSKID, ext.pskNonce);
                        }
                        // Create given KeyPackage
                        MLSMessage keyPackage = (MLSMessage) MLSInputStream.decode(key_package, MLSMessage.class);

                        // Verifying that the given private keys correspond to the public keys in key package
                        AsymmetricCipherKeyPair sigKeyPair = suite.deserializeSignaturePrivateKey(signature_priv);
                        byte[] sigPub = suite.serializeSignaturePublicKey(sigKeyPair.getPublic());
                        assertTrue(Arrays.areEqual(keyPackage.keyPackage.leaf_node.signature_key, sigPub));

                        byte[] leafPub = suite.getHPKE().serializePublicKey(leafKeyPair.getPublic());
                        assertTrue(Arrays.areEqual(keyPackage.keyPackage.leaf_node.encryption_key, leafPub));

                        AsymmetricCipherKeyPair initKeyPair = suite.getHPKE().deserializePrivateKey(init_priv, null);
                        byte[] initPub = suite.getHPKE().serializePublicKey(initKeyPair.getPublic());
                        assertTrue(Arrays.areEqual(keyPackage.keyPackage.init_key, initPub));


                        // Create given Welcome
                        MLSMessage welcomeMsg = (MLSMessage) MLSInputStream.decode(welcome, MLSMessage.class);

                        // Create and join Group using welcome
                        Group group = new Group(
                                init_priv,
                                leafKeyPair,
                                signature_priv,
                                keyPackage.keyPackage,
                                welcomeMsg.welcome,
                                tree,
                                externalPsks,
                                new HashMap<>()
                        );

                        assertTrue(Arrays.areEqual(group.getEpochAuthenticator(), initial_epoch_authenticator));

                        // verify if new member can follow along with the group
                        for (Epoch ep : epochs)
                        {
                            for (byte[] proposal : ep.proposals)
                            {
                                group.handle(proposal, null);
                            }
                            group = group.handle(ep.commit, null);
                            assertTrue(Arrays.areEqual(group.getEpochAuthenticator(), ep.epoch_authenticator));
                        }


                        externalPSKs.clear();
                        epochs.clear();
                        buf.clear();
                        count++;
                        System.out.println(" PASSED");
                    }
                    catch (Exception e)
                    {
                        System.out.println(" FAILED -> " + e.getMessage());

                        externalPSKs.clear();
                        epochs.clear();
                        buf.clear();
                        count++;
                        continue;
                    }
                }
            }
            if (!readingStack.isEmpty() && readingStack.peek().equals("external_psks"))
            {
                int a = line.indexOf("=");
                byte[] psk_id = Hex.decode(line.substring(a + 1).trim());
                line = bin.readLine();
                line = line.trim();
                a = line.indexOf("=");
                byte[] psk = Hex.decode(line.substring(a + 1).trim());

                PreSharedKeyID external = PreSharedKeyID.external(psk_id, psk);
                externalPSKs.add(external);
                continue;
            }
            if (!readingStack.isEmpty() && readingStack.peek().equals("proposals"))
            {
                byte[] proposal = Hex.decode(line.trim());
                proposals.add(proposal);
                continue;
            }
            if (!readingStack.isEmpty() && readingStack.peek().equals("epochs"))
            {
                int a = line.indexOf("=");
                byte[] commit = Hex.decode(line.substring(a + 1).trim());
                line = bin.readLine();
                line = line.trim();
                a = line.indexOf("=");
                byte[] epochAuth = Hex.decode(line.substring(a + 1).trim());

                epochs.add(new Epoch(proposals, commit, epochAuth));
                proposals.clear();
                continue;
            }
            int a = line.indexOf("=");
            if (a > -1)
            {
                buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }

        }
    }

}
