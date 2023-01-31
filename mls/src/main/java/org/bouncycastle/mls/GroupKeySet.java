package org.bouncycastle.mls;

import org.bouncycastle.mls.crypto.CipherSuite;
import org.bouncycastle.mls.crypto.Secret;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidParameterException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class GroupKeySet {
    final CipherSuite suite;
    final int secretSize;
    // We store a commitment to the encryption secret that was used to create this structure, so that we can compare
    // for  purposes of equivalence checking without violating forward secrecy.
    final Secret encryptionSecretCommit;

    SecretTree secretTree;
    Map<LeafIndex, HashRatchet> handshakeRatchets;
    Map<LeafIndex, HashRatchet> applicationRatchets;


    public GroupKeySet(CipherSuite suite, TreeSize treeSize, Secret encryptionSecret) throws IOException, IllegalAccessException {
        this.suite = suite;
        this.secretSize = suite.getKDF().getHashLength();
        this.encryptionSecretCommit = encryptionSecret.deriveSecret(suite, "commitment");
        this.secretTree = new SecretTree(treeSize, encryptionSecret);
        this.handshakeRatchets = new HashMap<>();
        this.applicationRatchets = new HashMap<>();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        GroupKeySet that = (GroupKeySet) o;
        return secretSize == that.secretSize && suite.equals(that.suite) && encryptionSecretCommit.equals(that.encryptionSecretCommit);
    }

    void initRatchets(LeafIndex sender) throws IOException, IllegalAccessException {
        Secret leafSecret = secretTree.get(sender);

        Secret handshakeRatchetSecret = leafSecret.expandWithLabel(suite, "handshake", new byte[]{}, secretSize);
        Secret applicationRatchetSecret = leafSecret.expandWithLabel(suite, "application", new byte[]{}, secretSize);

        HashRatchet handshakeRatchet = new HashRatchet(handshakeRatchetSecret);
        HashRatchet applicationRatchet = new HashRatchet(applicationRatchetSecret);

        handshakeRatchets.put(sender, handshakeRatchet);
        applicationRatchets.put(sender, applicationRatchet);
    }

    public HashRatchet handshakeRatchet(LeafIndex sender) throws IOException, IllegalAccessException {
        if (!handshakeRatchets.containsKey(sender)) {
            initRatchets(sender);
        }
        return handshakeRatchets.get(sender);
    }

    public HashRatchet applicationRatchet(LeafIndex sender) throws IOException, IllegalAccessException {
        if (!applicationRatchets.containsKey(sender)) {
            initRatchets(sender);
        }
        return applicationRatchets.get(sender);
    }

    public class SecretTree {
        final TreeSize treeSize;
        Map<NodeIndex, Secret> secrets;

        public SecretTree(TreeSize treeSizeIn, Secret encryptionSecret) {
            treeSize = treeSizeIn;
            secrets = new HashMap<>();
            secrets.put(NodeIndex.root(treeSize), encryptionSecret);
        }

        public Secret get(LeafIndex leaf) throws IOException, IllegalAccessException {

            final byte[] leftLabel = "left".getBytes(StandardCharsets.UTF_8);
            final byte[] rightLabel = "right".getBytes(StandardCharsets.UTF_8);

            NodeIndex rootNode = NodeIndex.root(treeSize);
            NodeIndex leafNode = new NodeIndex(leaf);

            // Find an ancestor that is populated
            List<NodeIndex> dirpath = leaf.directPath(treeSize);
            dirpath.add(0, leafNode);
            dirpath.add(rootNode);
            int curr = 0;
            for (; curr < dirpath.size(); curr++) {
                if (secrets.containsKey(dirpath.get(curr))) {
                    break;
                }
            }

            if (curr > dirpath.size()) {
                throw new InvalidParameterException("No secret found to derive leaf key");
            }

            // Derive down
            for (; curr > 0; curr--) {
                NodeIndex currNode = dirpath.get(curr);
                NodeIndex left = currNode.left();
                NodeIndex right = currNode.right();

                Secret secret = secrets.get(currNode);
                secrets.put(left, secret.expandWithLabel(suite, "tree", leftLabel, secretSize));
                secrets.put(right, secret.expandWithLabel(suite, "tree", rightLabel, secretSize));
            }

            // Get the leaf secret
            Secret leafSecret = secrets.get(leafNode);

            // Forget the secrets along the direct path
            for (NodeIndex i : dirpath) {
                if (i.equals(leafNode)) {
                    continue;
                }

                if (secrets.containsKey(i)) {
                    secrets.get(i).consume();
                    secrets.remove(i);
                }
            }

            return leafSecret;
        }
    }

    public class HashRatchet {
        final int keySize;
        final int nonceSize;
        Secret nextSecret;
        int nextGeneration;
        Map<Integer, KeyGeneration> cache;

        HashRatchet(Secret baseSecret) {
            keySize = suite.getAEAD().getKeySize();
            nonceSize = suite.getAEAD().getNonceSize();
            nextGeneration = 0;
            nextSecret = baseSecret;
            cache = new HashMap<>();
        }

        public KeyGeneration next() throws IOException, IllegalAccessException {
            Secret key = nextSecret.deriveTreeSecret(suite, "key", nextGeneration, keySize);
            Secret nonce = nextSecret.deriveTreeSecret(suite, "nonce", nextGeneration, nonceSize);
            Secret secret = nextSecret.deriveTreeSecret(suite, "secret", nextGeneration, secretSize);

            KeyGeneration generation = new KeyGeneration(nextGeneration, key, nonce);

            nextGeneration += 1;
            nextSecret.consume();
            nextSecret = secret;

            cache.put(generation.generation, generation);
            return generation;
        }

        public KeyGeneration get(int generation) throws IOException, IllegalAccessException {
            if (cache.containsKey(generation)) {
                return cache.get(generation);
            }

            if (nextGeneration > generation) {
                throw new InvalidParameterException("Request for expired key");
            }

            while (nextGeneration < generation) {
                next();
            }

            return next();
        }

        public void erase(int generation) {
            if (cache.containsKey(generation)) {
                cache.get(generation).consume();
                cache.remove(generation);
            }
        }
    }
}
