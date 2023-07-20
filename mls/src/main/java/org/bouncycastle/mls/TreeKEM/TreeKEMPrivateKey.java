package org.bouncycastle.mls.TreeKEM;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.mls.codec.HPKECiphertext;
import org.bouncycastle.mls.codec.UpdatePath;
import org.bouncycastle.mls.crypto.CipherSuite;
import org.bouncycastle.mls.crypto.Secret;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.bouncycastle.mls.TreeKEM.Utils.removeLeaves;

public class TreeKEMPrivateKey
//    implements MLSInputStream.Readable, MLSOutputStream.Writable

{
    CipherSuite suite;
    LeafIndex index;
    public Secret updateSecret;
    public Map<NodeIndex, Secret> pathSecrets;
    public Map<NodeIndex, AsymmetricCipherKeyPair> privateKeyCache;

    public TreeKEMPrivateKey(CipherSuite suite, LeafIndex index)
    {
        this.suite = suite;
        this.index = index;
        pathSecrets = new HashMap<>();
        privateKeyCache = new HashMap<>();
    }

    public TreeKEMPrivateKey copy()
    {
        TreeKEMPrivateKey clone = new TreeKEMPrivateKey(suite, index);
        clone.pathSecrets.putAll(pathSecrets);
        clone.privateKeyCache.putAll(privateKeyCache);
        return clone;
    }

    public static TreeKEMPrivateKey solo(CipherSuite suite, LeafIndex index, AsymmetricCipherKeyPair leafPriv)
    {

        TreeKEMPrivateKey priv = new TreeKEMPrivateKey(suite, index);
        priv.privateKeyCache.put(new NodeIndex(index), leafPriv);
        return priv;
    }
    public static TreeKEMPrivateKey create(TreeKEMPublicKey pub, LeafIndex from, Secret leafSecret) throws IOException
    {
        TreeKEMPrivateKey priv = new TreeKEMPrivateKey(pub.suite, from);
        priv.implant(pub, new NodeIndex(from), leafSecret);//todo check
        return priv;
    }
    public static TreeKEMPrivateKey joiner(TreeKEMPublicKey pub, LeafIndex index, AsymmetricCipherKeyPair leafPriv,
                                           NodeIndex intersect, Secret pathSecret) throws IOException
    {
        TreeKEMPrivateKey priv = new TreeKEMPrivateKey(pub.suite, index);
        priv.privateKeyCache.put(new NodeIndex(index), leafPriv);

        if (pathSecret != null)
        {
            priv.implant(pub, intersect, pathSecret);
        }
        return priv;
    }

    public void dump() throws IOException
    {
        for (NodeIndex node :
                pathSecrets.keySet())
        {
            setPrivateKey(node);
        }

        System.out.println("Tree (priv)");
        System.out.println("  Index: " + (new NodeIndex(index)).value());

        System.out.println("  Secrets: ");
        for (NodeIndex n : pathSecrets.keySet())
        {
            Secret pathSecret = pathSecrets.get(n);
            Secret nodeSecret = pathSecret.deriveSecret(suite, "node");
            AsymmetricCipherKeyPair sk = suite.getHPKE().deriveKeyPair(nodeSecret.value());


            System.out.println("    " + n.value()
                    + " => " + Hex.toHexString(pathSecret.value(), 0, 4)
                    + " => " + Hex.toHexString(suite.getHPKE().serializePublicKey(sk.getPublic()), 0, 4));
        }

        System.out.println("  Cached key pairs: ");
        for (NodeIndex n: privateKeyCache.keySet())
        {
            AsymmetricCipherKeyPair sk = privateKeyCache.get(n);
            System.out.println("    " + n.value() + " => " + Hex.toHexString(suite.getHPKE().serializePublicKey(sk.getPublic()), 0, 4));
        }
    }
    public void decap(LeafIndex from, TreeKEMPublicKey pub, byte[] context, UpdatePath path, List<LeafIndex> except) throws Exception
    {
        // find decap target
        NodeIndex ni = new NodeIndex(index);
        FilteredDirectPath dp = pub.getFilteredDirectPath(new NodeIndex(from));
        if (dp.parents.size() != path.nodes.size())
        {
            throw new Exception("Malformed direct path");
        }

        int dpi = 0;
        NodeIndex overlapNode = null;
        ArrayList<NodeIndex> res = new ArrayList<>();
        for (dpi = 0; dpi < dp.parents.size(); dpi++)
        {
            if (ni.isBelow(dp.parents.get(dpi)))
            {
                overlapNode = dp.parents.get(dpi);
                res = dp.resolutions.get(dpi);
                break;
            }
        }

        if (dpi == dp.parents.size())
        {
            throw new Exception("No overlap in path");
        }

        // find target in resolution
        removeLeaves(res, except);
        if (res.size() != path.nodes.get(dpi).encrypted_path_secret.size())
        {
            throw new Exception("Malformed direct path node");
        }

        int resi = 0;
        for (resi = 0; resi < res.size(); resi++)
        {
            if (havePrivateKey(res.get(resi)))
            {
                break;
            }
        }

        if (resi == res.size())
        {
            throw new Exception("No private key to decrypt path secret");
        }

        // decrypt and implant
        AsymmetricCipherKeyPair priv = getPrivateKey(res.get(resi));
        HPKECiphertext ct = path.nodes.get(dpi).encrypted_path_secret.get(resi);

        Secret pathSecret = new Secret(suite.decryptWithLabel(
                suite.getHPKE().serializePrivateKey(priv.getPrivate()),
                "UpdatePathNode",
                context,
                ct.kem_output,
                ct.ciphertext)
        );

        implant(pub, overlapNode, pathSecret);

        if(!consistent(pub))
        {
            throw new Exception("TreeKEMPublicKey inconsistant with TreeKEMPrivateKey");
        }
    }

    private boolean havePrivateKey(NodeIndex n)
    {
        return pathSecrets.containsKey(n) || privateKeyCache.containsKey(n);
    }

    public boolean consistent(TreeKEMPublicKey other) throws IOException
    {
        if (suite.getSuiteId() != other.suite.getSuiteId())
        {
            return false;
        }

        for (NodeIndex node : pathSecrets.keySet())
        {
            setPrivateKey(node);
        }

        for (NodeIndex key : privateKeyCache.keySet())
        {
            Node optNode = other.nodeAt(key).node;
            if (optNode == null)
            {
                continue;
            }
            byte[] pub = optNode.getPublicKey();
            AsymmetricCipherKeyPair priv = privateKeyCache.get(key);
            // todo maybe i have to initilize the public keys for testing
            if (!Arrays.equals(pub, suite.getHPKE().serializePublicKey(priv.getPublic())))
            {
                return false;
            }
        }
        return true;
    }

    private AsymmetricCipherKeyPair setPrivateKey(NodeIndex n) throws IOException
    {
        AsymmetricCipherKeyPair priv = getPrivateKey(n);
        if (priv != null)
        {
            //TODO: Why is this adding more than what we want???
            privateKeyCache.put(n, priv);
        }
        return priv;
    }
    protected AsymmetricCipherKeyPair getPrivateKey(NodeIndex n) throws IOException
    {
        if (privateKeyCache.containsKey(n))
        {
            return privateKeyCache.get(n);
        }
        if (!pathSecrets.containsKey(n))
        {
            return null;
        }

        Secret nodeSecret = pathSecrets.get(n).deriveSecret(suite, "node");
        return suite.getHPKE().deriveKeyPair(nodeSecret.value());
    }

    private void implant(TreeKEMPublicKey pub, NodeIndex start, Secret pathSecret) throws IOException
    {
        FilteredDirectPath fdp = pub.getFilteredDirectPath(start);
        Secret secret = new Secret(pathSecret.value());

        pathSecrets.put(start, secret);
        privateKeyCache.remove(start);

        for (NodeIndex n : fdp.parents)
        {
            secret = secret.deriveSecret(pub.suite, "path");
            pathSecrets.put(n, secret);
            privateKeyCache.remove(n);
        }

        updateSecret = secret.deriveSecret(pub.suite, "path");
    }

    public Secret getSharedPathSecret(LeafIndex to)
    {
        //TODO: make a triplet class
        NodeIndex n = index.commonAncestor(to);
        if (!pathSecrets.containsKey(n))
        {
            return new Secret(new byte[0]);
        }
        return pathSecrets.get(n);
    }

}
