package org.bouncycastle.mls.test;

import junit.framework.TestCase;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.mls.*;
import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSOutputStream;
import org.bouncycastle.mls.crypto.CipherSuite;
import org.bouncycastle.mls.crypto.Secret;
import org.bouncycastle.mls.protocol.GroupContext;
import org.bouncycastle.mls.protocol.PreSharedKeyID;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.encoders.Hex;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class VectorTest
        extends TestCase
{
    public void testTreeMath()
            throws Exception
    {
        InputStream src = VectorTest.class.getResourceAsStream("tree-math.txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line;
        HashMap<String, String> buf = new HashMap<String, String>();
        ArrayList<Long> left = new ArrayList<Long>();
        ArrayList<Long> right = new ArrayList<Long>();
        ArrayList<Long> parent = new ArrayList<Long>();
        ArrayList<Long> sibling = new ArrayList<Long>();
        ArrayList<Long> temp = new ArrayList<Long>();
        int arrCount = 0;


        int count = 0;

        while((line = bin.readLine())!= null)
        {
            line = line.trim();
            if (line.length() == 0)
            {
                if (buf.size() > 0)
                {
                    System.out.println("test case: " + count);
                    long n_leaves = Long.parseLong((String)buf.get("n_leaves"));
                    long n_nodes = Long.parseLong((String)buf.get("n_nodes"));
                    long root = Long.parseLong((String)buf.get("root"));
                    TreeSize treeSize = TreeSize.forLeaves(n_leaves);

                    assertEquals(root, NodeIndex.root(treeSize).value());
                    assertEquals(n_nodes, treeSize.width());
                    for (int i = 0; i < treeSize.width(); i++)
                    {
                        NodeIndex n = new NodeIndex(i);

                        // ignoring null value checks
                        assertEquals(left.get(i) == -1 ? i : left.get(i), n.left().value());
                        assertEquals(right.get(i) == -1 ? i : right.get(i), n.right().value());
                        assertEquals(parent.get(i) == -1 ? n.parent().value() : parent.get(i), n.parent().value());
                        assertEquals(sibling.get(i) == -1 ? n.sibling().value() : sibling.get(i), n.sibling().value());
                    }


                    count++;
                }
            }
            int a = line.indexOf("=");
            if (a > -1)
            {
                buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
            if (line.endsWith("START"))
            {
                while ((line = bin.readLine()) != null)
                {
                    line = line.trim();
                    if (line.endsWith("STOP"))
                    {
                        switch (arrCount)
                        {
                            case 0:
                                left = (ArrayList<Long>) temp.clone();
                                break;
                            case 1:
                                right = (ArrayList<Long>) temp.clone();
                                break;
                            case 2:
                                parent = (ArrayList<Long>) temp.clone();
                                break;
                            case 3:
                                sibling = (ArrayList<Long>) temp.clone();
                                break;
                        }
                        arrCount = (++arrCount % 4);
                        temp.clear();
                        break;
                    }
                    long val;
                    if(line.equals("null"))
                    {
                        val = -1;
                    }
                    else
                    {
                        val = Long.parseLong((String)line);
                    }
                    temp.add(val);
                }
            }
        }
    }

    public void testCryptoBasics()
            throws Exception
    {
        InputStream src = VectorTest.class.getResourceAsStream("crypto-basics.txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line;
        HashMap<String, String> buf = new HashMap<String, String>();
        int arrCount = 0;


        int count = 0;

        while((line = bin.readLine())!= null)
        {
            line = line.trim();
            if (line.length() == 0)
            {
                if (buf.size() > 0)
                {
                    System.out.println("test case: " + count);
                    short cipherSuite = Short.parseShort(buf.get("cipherSuite"));
                    String refHash_label = buf.get("refHash_label");
                    byte[] refHash_value = Hex.decode(buf.get("refHash_value"));
                    byte[] refHash_out = Hex.decode(buf.get("refHash_out"));

                    byte[] expandWithLabel_secret = Hex.decode(buf.get("expandWithLabel_secret"));
                    String expandWithLabel_label = buf.get("expandWithLabel_label");
                    byte[] expandWithLabel_context = Hex.decode(buf.get("expandWithLabel_context"));
                    short expandWithLabel_length = Short.parseShort(buf.get("expandWithLabel_length"));
                    byte[] expandWithLabel_out = Hex.decode(buf.get("expandWithLabel_out"));

                    byte[] deriveSecret_secret = Hex.decode(buf.get("deriveSecret_secret"));
                    String deriveSecret_label = buf.get("deriveSecret_label");
                    byte[] deriveSecret_out = Hex.decode(buf.get("deriveSecret_out"));

                    byte[] deriveTreeSecret_secret = Hex.decode(buf.get("deriveTreeSecret_secret"));
                    String deriveTreeSecret_label = buf.get("deriveTreeSecret_label");
                    int deriveTreeSecret_generation = Integer.parseUnsignedInt(buf.get("deriveTreeSecret_generation"));
                    short deriveTreeSecret_length = Short.parseShort(buf.get("deriveTreeSecret_length"));
                    byte[] deriveTreeSecret_out = Hex.decode(buf.get("deriveTreeSecret_out"));

                    byte[] signWithLabel_priv = Hex.decode(buf.get("signWithLabel_priv"));
                    byte[] signWithLabel_pub = Hex.decode(buf.get("signWithLabel_pub"));
                    byte[] signWithLabel_content = Hex.decode(buf.get("signWithLabel_content"));
                    String signWithLabel_label = buf.get("signWithLabel_label");
                    byte[] signWithLabel_signature = Hex.decode(buf.get("signWithLabel_signature"));

                    byte[] encryptWithLabel_priv = Hex.decode(buf.get("encryptWithLabel_priv"));
                    byte[] encryptWithLabel_pub = Hex.decode(buf.get("encryptWithLabel_pub"));
                    String encryptWithLabel_label = buf.get("encryptWithLabel_label");
                    byte[] encryptWithLabel_context = Hex.decode(buf.get("encryptWithLabel_context"));
                    byte[] encryptWithLabel_plaintext = Hex.decode(buf.get("encryptWithLabel_plaintext"));
                    byte[] encryptWithLabel_kemOutput = Hex.decode(buf.get("encryptWithLabel_kemOutput"));
                    byte[] encryptWithLabel_ciphertext = Hex.decode(buf.get("encryptWithLabel_ciphertext"));

                    CipherSuite suite = new CipherSuite(cipherSuite);

                    // ref_hash: out == RefHash(label, value)
                    byte[] refOut = suite.refHash( refHash_value, refHash_label);
                    assertTrue(Arrays.areEqual(refHash_out, refOut));

                    // expand_with_label: out == ExpandWithLabel(secret, label, context, length)
                    byte[] expandWithLabelOut = suite.getKDF().expandWithLabel(expandWithLabel_secret, expandWithLabel_label, expandWithLabel_context, expandWithLabel_length);
                    assertTrue(Arrays.areEqual(expandWithLabel_out, expandWithLabelOut));

                    // Using Secret Class
                    Secret secret = new Secret(expandWithLabel_secret);
                    expandWithLabelOut = secret.expandWithLabel(suite, expandWithLabel_label, expandWithLabel_context, expandWithLabel_length).value();
                    assertTrue(Arrays.areEqual(expandWithLabel_out, expandWithLabelOut));


                    // derive_secret: out == DeriveSecret(secret, label)
                    byte[] deriveSecretOut = suite.getKDF().expandWithLabel(deriveSecret_secret, deriveSecret_label, new byte[] {}, suite.getKDF().getHashLength());
                    assertTrue(Arrays.areEqual(deriveSecret_out, deriveSecretOut));

                    // Using Secret Class
                    secret = new Secret(deriveSecret_secret);
                    deriveSecretOut = secret.deriveSecret(suite, deriveSecret_label).value();
                    assertTrue(Arrays.areEqual(deriveSecret_out, deriveSecretOut));


                    // derive_tree_secret: out == DeriveTreeSecret(secret, label, generation, length)
                    byte[] deriveTreeSecretOut = suite.getKDF().expandWithLabel(deriveTreeSecret_secret, deriveTreeSecret_label, Pack.intToBigEndian(deriveTreeSecret_generation), deriveTreeSecret_length);
                    assertTrue(Arrays.areEqual(deriveTreeSecret_out, deriveTreeSecretOut));

                    // Using Secret class
                    secret = new Secret(deriveTreeSecret_secret);
                    deriveTreeSecretOut = secret.deriveTreeSecret(suite, deriveTreeSecret_label, deriveTreeSecret_generation, deriveTreeSecret_length).value();
                    assertTrue(Arrays.areEqual(deriveTreeSecret_out, deriveTreeSecretOut));


                    // sign_with_label:
                    //      VerifyWithLabel(pub, label, content, signature) == true
                    boolean verifyWithLabel = suite.verifyWithLabel(signWithLabel_pub, signWithLabel_label, signWithLabel_content, signWithLabel_signature);
                    assertTrue(verifyWithLabel);
                    //      VerifyWithLabel(pub, label, content, SignWithLabel(priv, label, content)) == true
                    byte[] signatureWithLabel = suite.signWithLabel(signWithLabel_priv, signWithLabel_label, signWithLabel_content);
                    verifyWithLabel = suite.verifyWithLabel(signWithLabel_pub, signWithLabel_label, signWithLabel_content, signatureWithLabel);
                    assertTrue(verifyWithLabel);


                    // encrypt_with_label:
                    //      DecryptWithLabel(priv, label, context, kem_output, ciphertext) == plaintext
                    byte[] plaintextOut = suite.decryptWithLabel(encryptWithLabel_priv, encryptWithLabel_label, encryptWithLabel_context, encryptWithLabel_kemOutput, encryptWithLabel_ciphertext);
                    assertTrue(Arrays.areEqual(plaintextOut, encryptWithLabel_plaintext));
                    //      kem_output_candidate, ciphertext_candidate = EncryptWithLabel(pub, label, context, plaintext)
                    byte[][] encryptWithLabelOut = suite.encryptWithLabel(encryptWithLabel_pub, encryptWithLabel_label, encryptWithLabel_context, encryptWithLabel_plaintext);
                    byte[] kem_output_candidate = encryptWithLabelOut[1];
                    byte[] ciphertext_candidate = encryptWithLabelOut[0];
                    //      DecryptWithLabel(priv, label, context, kem_output_candidate, ciphertext_candidate) == plaintext
                    plaintextOut = suite.decryptWithLabel(encryptWithLabel_priv, encryptWithLabel_label, encryptWithLabel_context, kem_output_candidate, ciphertext_candidate);
                    assertTrue(Arrays.areEqual(plaintextOut, encryptWithLabel_plaintext));

                    count++;
                }
            }
            int a = line.indexOf("=");
            if (a > -1)
            {
                buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
        }

    }

    public void testSecretTree()
            throws Exception
    {
        class LeafInfo
        {
            int generation;
            byte[] application_key;
            byte[] application_nonce;
            byte[] handshake_key;
            byte[] handshake_nonce;

            public LeafInfo(int generation, byte[] application_key, byte[] application_nonce, byte[] handshake_key, byte[] handshake_nonce)
            {
                this.generation = generation;
                this.application_key = application_key;
                this.application_nonce = application_nonce;
                this.handshake_key = handshake_key;
                this.handshake_nonce = handshake_nonce;
            }
        }
        InputStream src = VectorTest.class.getResourceAsStream("secret-tree.txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line;
        HashMap<String, String> buf = new HashMap<String, String>();
        HashMap<String, String> bufLeaf = new HashMap<String, String>();
        ArrayList<LeafInfo[]> leaves = new ArrayList<LeafInfo[]>();
        int leafCounter = 0;
        LeafInfo[] tempLeaf = null;
        int count = 0;

        while((line = bin.readLine())!= null)
        {
            line = line.trim();
            if (line.length() == 0)
            {
                if (buf.size() > 0)
                {
                    System.out.println("test case: " + count);
                    short cipher_suite = Short.parseShort(buf.get("cipher_suite"));
                    byte[] encryption_secret = Hex.decode(buf.get("encryption_secret"));
                    byte[] sender_data_secret = Hex.decode(buf.get("sender_data_secret"));
                    byte[] ciphertext = Hex.decode(buf.get("ciphertext"));
                    byte[] key = Hex.decode(buf.get("key"));
                    byte[] nonce = Hex.decode(buf.get("nonce"));
                    CipherSuite suite = new CipherSuite(cipher_suite);

                    // sender_data:
                    //      key == sender_data_key(sender_data_secret, ciphertext)
                    byte[] ciphertext_sample = Arrays.copyOf(ciphertext, suite.getKDF().getHashLength());
                    byte[] sender_data_key = suite.getKDF().expandWithLabel(sender_data_secret, "key", ciphertext_sample, suite.getAEAD().getKeySize());
                    assertTrue(Arrays.areEqual(sender_data_key, key));
                    //      nonce == sender_data_nonce(sender_data_secret, ciphertext)
                    byte[] sender_data_nonce = suite.getKDF().expandWithLabel(sender_data_secret, "nonce", ciphertext_sample, suite.getAEAD().getNonceSize());
                    assertTrue(Arrays.areEqual(sender_data_nonce, nonce));

                    // Initialize a secret tree with a number of leaves equal to the number of entries
                    // in the leaves array, with encryption_secret as the root secret
                    TreeSize treeSize = TreeSize.forLeaves(leaves.size());
                    Secret root = new Secret(encryption_secret);
                    GroupKeySet keys = new GroupKeySet(suite, treeSize, root);


                    // For each entry in the array leaves[i], verify that:
                    //      handshake_key = handshake_ratchet_key_[i]_[generation]
                    //      handshake_nonce = handshake_ratchet_nonce_[i]_[generation]
                    //      application_key = application_ratchet_key_[i]_[generation]
                    //      application_nonce = application_ratchet_nonce_[i]_[generation]
                    for (int i = 0; i < leaves.size(); i++)
                    {
                        for (LeafInfo leafinfo: leaves.get(i))
                        {
                            LeafIndex leafNode = new LeafIndex(i);
                            KeyGeneration hsGen = keys.handshakeRatchet(leafNode).get(leafinfo.generation);
                            KeyGeneration appGen = keys.applicationRatchet(leafNode).get(leafinfo.generation);

                            assertTrue(Arrays.areEqual(hsGen.key, leafinfo.handshake_key));
                            assertTrue(Arrays.areEqual(hsGen.nonce, leafinfo.handshake_nonce));
                            assertTrue(Arrays.areEqual(appGen.key, leafinfo.application_key));
                            assertTrue(Arrays.areEqual(appGen.nonce, leafinfo.application_nonce));
                        }
                    }

                    buf.clear();
                    leaves.clear();
                    count++;
                }
            }
            int a = line.indexOf("=");
            if (a > -1)
            {
                buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
            if (line.endsWith("START"))
            {
                while ((line = bin.readLine()) != null)
                {
                    line = line.trim();
                    if(line.endsWith("STOP"))
                    {
                        break;
                    }
                    if (line.length() == 0)
                    {
                        if (bufLeaf.size() > 0)
                        {

                            int generation = Integer.parseUnsignedInt(bufLeaf.get("generation"));
                            byte[] application_key = Hex.decode(bufLeaf.get("application_key"));
                            byte[] application_nonce = Hex.decode(bufLeaf.get("application_nonce"));
                            byte[] handshake_key = Hex.decode(bufLeaf.get("handshake_key"));
                            byte[] handshake_nonce = Hex.decode(bufLeaf.get("handshake_nonce"));
                            if(leafCounter == 0)
                            {
                                tempLeaf = new LeafInfo[2];
                            }
                            tempLeaf[leafCounter] = new LeafInfo(generation, application_key, application_nonce, handshake_key, handshake_nonce);
                            if (leafCounter == 1)
                            {
                                leaves.add(tempLeaf);
                            }

                            leafCounter = (++leafCounter)%2;
                            bufLeaf.clear();
                        }
                    }
                    int b = line.indexOf("=");
                    if (b > -1)
                    {
                        bufLeaf.put(line.substring(0, b).trim(), line.substring(b + 1).trim());
                    }
                }
            }
        }
    }

    public void testMessageProtection()
            throws Exception
    {
        InputStream src = VectorTest.class.getResourceAsStream("message-protection.txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line;
        HashMap<String, String> buf = new HashMap<String, String>();
        int count = 0;

        while((line = bin.readLine())!= null)
        {
            line = line.trim();
            if (line.length() == 0)
            {
                if (buf.size() > 0)
                {
                    System.out.println("test case: " + count);
                    short cipher_suite = Short.parseShort(buf.get("cipher_suite"));
                    byte[] group_id = Hex.decode(buf.get("group_id"));
                    long epoch = Long.parseLong(buf.get("epoch"));
                    byte[] tree_hash = Hex.decode(buf.get("tree_hash"));
                    byte[] confirmed_transcript_hash = Hex.decode(buf.get("confirmed_transcript_hash"));
                    byte[] signature_priv = Hex.decode(buf.get("signature_priv"));
                    byte[] signature_pub = Hex.decode(buf.get("signature_pub"));
                    byte[] encryption_secret = Hex.decode(buf.get("encryption_secret"));
                    byte[] sender_data_secret = Hex.decode(buf.get("sender_data_secret"));
                    byte[] membership_key = Hex.decode(buf.get("membership_key"));
                    byte[] proposal = Hex.decode(buf.get("proposal"));
                    byte[] proposal_priv = Hex.decode(buf.get("proposal_priv"));
                    byte[] proposal_pub = Hex.decode(buf.get("proposal_pub"));
                    byte[] commit = Hex.decode(buf.get("commit"));
                    byte[] commit_priv = Hex.decode(buf.get("commit_priv"));
                    byte[] commit_pub = Hex.decode(buf.get("commit_pub"));
                    byte[] application = Hex.decode(buf.get("application"));
                    byte[] application_priv = Hex.decode(buf.get("application_priv"));

                    CipherSuite suite = new CipherSuite(cipher_suite);

                    // Construct a GroupContext object with the provided cipher_suite, group_id, epoch, tree_hash,
                    // and confirmed_transcript_hash values, and empty extensions
                    GroupContext groupContext = new GroupContext(cipher_suite, group_id, epoch, tree_hash, confirmed_transcript_hash, new byte[0]);

                    // Initialize a secret tree for 2 members with the specified encryption_secret
                    TreeSize treeSize = TreeSize.forLeaves(2);
                    Secret root = new Secret(encryption_secret);
                    GroupKeySet keys = new GroupKeySet(suite, treeSize, root);

                    // Proposal
                    System.out.println("proposal: " + Hex.toHexString(proposal));
//                    byte[] decrypted_message =

                    // Commit

                    // Application




                    count++;
                }
            }
            int a = line.indexOf("=");
            if (a > -1)
            {
                buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
        }
    }

    public void testKeySchedule()
            throws Exception
    {
        InputStream src = VectorTest.class.getResourceAsStream("key-schedule.txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line;
        HashMap<String, String> buf = new HashMap<String, String>();
        HashMap<String, String> bufEpoch = new HashMap<String, String>();
        Secret prevEpochSecret = null;
        int count = 0;
        int epochCount = 0;

        while((line = bin.readLine())!= null)
        {
            line = line.trim();
            if (line.length() == 0)
            {
                if (buf.size() > 0)
                {
                    System.out.println("test case: " + count);
                    buf.clear();
                    bufEpoch.clear();
                    count++;
                    epochCount = 0;

                }
            }
            int a = line.indexOf("=");
            if (a > -1)
            {
                buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
            if (line.endsWith("START"))
            {
                while ((line = bin.readLine()) != null)
                {
                    line = line.trim();
                    if(line.endsWith("STOP"))
                    {

                        break;
                    }
                    if (line.length() == 0)
                    {
                        if (bufEpoch.size() > 0)
                        {
//                            System.out.println("test case: " + count + " epoch: " + epochCount );
                            byte[] commit_secret = Hex.decode(bufEpoch.get("commit_secret"));
                            byte[] confirmation_key = Hex.decode(bufEpoch.get("confirmation_key"));
                            byte[] confirmed_transcript_hash = Hex.decode(bufEpoch.get("confirmed_transcript_hash"));
                            byte[] encryption_secret = Hex.decode(bufEpoch.get("encryption_secret"));
                            byte[] epoch_authenticator = Hex.decode(bufEpoch.get("epoch_authenticator"));
                            byte[] exporterContext = Hex.decode(bufEpoch.get("exporterContext"));
                            String exporterLabel = bufEpoch.get("exporterLabel");
                            int exporterLength = Integer.parseInt(bufEpoch.get("exporterLength"));
                            byte[] exporterSecret = Hex.decode(bufEpoch.get("exporterSecret"));
                            byte[] exporter_secret = Hex.decode(bufEpoch.get("exporter_secret"));
                            byte[] external_pub = Hex.decode(bufEpoch.get("external_pub"));
                            byte[] external_secret = Hex.decode(bufEpoch.get("external_secret"));
                            byte[] group_context = Hex.decode(bufEpoch.get("group_context"));
                            byte[] init_secret = Hex.decode(bufEpoch.get("init_secret"));
                            byte[] joiner_secret = Hex.decode(bufEpoch.get("joiner_secret"));
                            byte[] membership_key = Hex.decode(bufEpoch.get("membership_key"));
                            byte[] psk_secret = Hex.decode(bufEpoch.get("psk_secret"));
                            byte[] resumption_psk = Hex.decode(bufEpoch.get("resumption_psk"));
                            byte[] sender_data_secret = Hex.decode(bufEpoch.get("sender_data_secret"));
                            byte[] tree_hash = Hex.decode(bufEpoch.get("tree_hash"));
                            byte[] welcome_secret = Hex.decode(bufEpoch.get("welcome_secret"));

                            short cipher_suite = Short.parseShort(buf.get("cipher_suite"));
                            byte[] group_id = Hex.decode(buf.get("group_id"));
                            byte[] initial_init_secret = Hex.decode(buf.get("initial_init_secret"));
                            CipherSuite suite = new CipherSuite(cipher_suite);

                            GroupContext groupContext = new GroupContext(
                                    cipher_suite,
                                    group_id,
                                    epochCount,
                                    tree_hash,
                                    confirmed_transcript_hash,
                                    new byte[0]
                            );
                            // Verify that group context matches the provided group_context value
                            byte[] groupContextBytes = MLSOutputStream.encode(groupContext);
                            assertTrue(Arrays.areEqual(group_context, groupContextBytes));

                            // Initialize the creator's key schedule
                            TreeSize treeSize = TreeSize.forLeaves(1+epochCount);
                            KeyScheduleEpoch.JoinSecrets joinSecrets;
                            if(epochCount == 0)
                            {
                                prevEpochSecret = new Secret(initial_init_secret);
                            }

                            joinSecrets = KeyScheduleEpoch.JoinSecrets.forMember(suite, prevEpochSecret, new Secret(commit_secret), null, group_context);
                            joinSecrets.injectPskSecret(new Secret(psk_secret));
                            assertTrue(Arrays.areEqual(joiner_secret, joinSecrets.joinerSecret.value()));
                            assertTrue(Arrays.areEqual(welcome_secret, joinSecrets.welcomeSecret.value()));

                            KeyScheduleEpoch epoch = joinSecrets.complete(treeSize, group_context);
                            prevEpochSecret = epoch.initSecret;
                            assertTrue(Arrays.areEqual(init_secret, epoch.initSecret.value()));
                            assertTrue(Arrays.areEqual(sender_data_secret, epoch.senderDataSecret.value()));
                            assertTrue(Arrays.areEqual(encryption_secret, epoch.encryptionSecret.value()));
                            assertTrue(Arrays.areEqual(exporter_secret, epoch.exporterSecret.value()));
                            assertTrue(Arrays.areEqual(epoch_authenticator, epoch.epochAuthenticator.value()));
                            assertTrue(Arrays.areEqual(external_secret, epoch.externalSecret.value()));
                            assertTrue(Arrays.areEqual(confirmation_key, epoch.confirmationKey.value()));
                            assertTrue(Arrays.areEqual(membership_key, epoch.membershipKey.value()));
                            assertTrue(Arrays.areEqual(resumption_psk, epoch.resumptionPSK.value()));

                            byte[] externalPubBytes = suite.getHPKE().serializePublicKey(epoch.getExternalPublicKey());
                            assertTrue(Arrays.areEqual(external_pub, externalPubBytes));

                            byte[] exporterSecretBytes = epoch.MLSExporter(exporterLabel, exporterContext, exporterLength);
                            assertTrue(Arrays.areEqual(exporterSecret, exporterSecretBytes));




                            epochCount++;
                            bufEpoch.clear();
                        }
                    }
                    int b = line.indexOf("=");
                    if (b > -1)
                    {
                        bufEpoch.put(line.substring(0, b).trim(), line.substring(b + 1).trim());
                    }
                }
            }
        }
    }

    public void testPskSecret()
            throws Exception
    {
        class PSK
        {
            final byte[] psk_id;
            final byte[] psk;
            final byte[] psk_nonce;

            public PSK(byte[] psk_id, byte[] psk, byte[] psk_nonce)
            {
                this.psk_id = psk_id;
                this.psk = psk;
                this.psk_nonce = psk_nonce;
            }
        }
        InputStream src = VectorTest.class.getResourceAsStream("psk_secret.txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line;
        HashMap<String, String> buf = new HashMap<String, String>();
        HashMap<String, String> bufpsk = new HashMap<String, String>();
        ArrayList<PSK> psks = new ArrayList<PSK>();
        int count = 0;

        while((line = bin.readLine())!= null)
        {
            line = line.trim();
            if (line.length() == 0)
            {
                if (buf.size() > 0)
                {
                    System.out.println("test case: " + count);
                    short cipher_suite = Short.parseShort(buf.get("cipher_suite"));
                    byte[] psk_secret = Hex.decode(buf.get("psk_secret"));
                    CipherSuite suite = new CipherSuite(cipher_suite);

                    List<KeyScheduleEpoch.PSKWithSecret> pskList = new ArrayList<>();
                    for (PSK psk : psks)
                    {
                        PreSharedKeyID external = PreSharedKeyID.external(psk.psk_id, psk.psk_nonce);
                        KeyScheduleEpoch.PSKWithSecret temp = new KeyScheduleEpoch.PSKWithSecret(external, new Secret(psk.psk));
                        pskList.add(temp);
                    }

                    Secret pskOutput = KeyScheduleEpoch.JoinSecrets.pskSecret(suite, pskList);
                    assertTrue(Arrays.areEqual(psk_secret, pskOutput.value()));

                    buf.clear();
                    psks.clear();
                    count++;
                }
            }
            int a = line.indexOf("=");
            if (a > -1)
            {
                buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
            if (line.endsWith("START"))
            {
                while ((line = bin.readLine()) != null)
                {
                    line = line.trim();
                    if(line.endsWith("STOP"))
                    {
                        break;
                    }
                    if (line.length() == 0)
                    {
                        if (bufpsk.size() > 0)
                        {

                            byte[] psk_id = Hex.decode(bufpsk.get("psk_id"));
                            byte[] psk = Hex.decode(bufpsk.get("psk"));
                            byte[] psk_nonce = Hex.decode(bufpsk.get("psk_nonce"));

                            psks.add(new PSK(psk_id, psk, psk_nonce));
                            bufpsk.clear();
                        }
                    }
                    int b = line.indexOf("=");
                    if (b > -1)
                    {
                        bufpsk.put(line.substring(0, b).trim(), line.substring(b + 1).trim());
                    }
                }
            }
        }
    }



}
