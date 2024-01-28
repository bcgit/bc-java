package org.bouncycastle.mls.TreeKEM;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.mls.TreeSize;
import org.bouncycastle.mls.codec.HPKECiphertext;
import org.bouncycastle.mls.codec.UpdatePath;
import org.bouncycastle.mls.crypto.MlsCipherSuite;
import org.bouncycastle.mls.crypto.Secret;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import static org.bouncycastle.mls.TreeKEM.Utils.removeLeaves;

public class TreeKEMPrivateKey
{
    MlsCipherSuite suite;
    LeafIndex index;
    Secret updateSecret;
    Map<NodeIndex, Secret> pathSecrets;
    Map<NodeIndex, AsymmetricCipherKeyPair> privateKeyCache;

    public Secret getUpdateSecret()
    {
        return updateSecret;
    }

    public void insertPathSecret(NodeIndex index, Secret secret)
    {
        pathSecrets.put(index, secret);
    }

    public void insertPrivateKey(NodeIndex index, AsymmetricCipherKeyPair keyPair)
    {
        privateKeyCache.put(index, keyPair);
    }

    public TreeKEMPrivateKey(MlsCipherSuite suite, LeafIndex index)
    {
        this.suite = suite;
        this.index = index;
        pathSecrets = new HashMap<NodeIndex, Secret>();
        privateKeyCache = new HashMap<NodeIndex, AsymmetricCipherKeyPair>();
    }

    public TreeKEMPrivateKey copy()
    {
        TreeKEMPrivateKey clone = new TreeKEMPrivateKey(suite, index);
        clone.pathSecrets.putAll(pathSecrets);
        clone.privateKeyCache.putAll(privateKeyCache);
        return clone;
    }

    public static TreeKEMPrivateKey solo(MlsCipherSuite suite, LeafIndex index, AsymmetricCipherKeyPair leafPriv)
    {

        TreeKEMPrivateKey priv = new TreeKEMPrivateKey(suite, index);
        priv.privateKeyCache.put(new NodeIndex(index), leafPriv);
        return priv;
    }

    public static TreeKEMPrivateKey create(TreeKEMPublicKey pub, LeafIndex from, Secret leafSecret)
        throws Exception
    {
        TreeKEMPrivateKey priv = new TreeKEMPrivateKey(pub.suite, from);
        priv.implant(pub, new NodeIndex(from), leafSecret);
        return priv;
    }

    public static TreeKEMPrivateKey joiner(TreeKEMPublicKey pub, LeafIndex index, AsymmetricCipherKeyPair leafPriv,
                                           NodeIndex intersect, Secret pathSecret)
        throws Exception
    {
        TreeKEMPrivateKey priv = new TreeKEMPrivateKey(pub.suite, index);

        priv.privateKeyCache.put(new NodeIndex(index), leafPriv);

        if (pathSecret != null)
        {
            priv.implant(pub, intersect, pathSecret);
        }
        return priv;
    }

    public String dump()
        throws IOException
    {
        StringBuilder sb = new StringBuilder();
        for (NodeIndex node :
            pathSecrets.keySet())
        {
            setPrivateKey(node, true);
        }

        sb.append("Tree (priv)").append(Strings.lineSeparator());
        sb.append("  Index: ").append((new NodeIndex(index)).value()).append(Strings.lineSeparator());

        sb.append("  Secrets: ").append(Strings.lineSeparator());
        for (NodeIndex n : pathSecrets.keySet())
        {
            Secret pathSecret = pathSecrets.get(n);
            Secret nodeSecret = pathSecret.deriveSecret(suite, "node");
            AsymmetricCipherKeyPair sk = suite.getHPKE().deriveKeyPair(nodeSecret.value());

            // -DM Hex.toHexString
            // -DM Hex.toHexString
            sb.append("    ").append(n.value())
                    .append(" => ").append(Hex.toHexString(pathSecret.value(), 0, 4))
                    .append(" => ").append(Hex.toHexString(suite.getHPKE().serializePublicKey(sk.getPublic()), 0, 4))
                    .append(Strings.lineSeparator());
        }

        sb.append("  Cached key pairs: ").append(Strings.lineSeparator());
        for (NodeIndex n : privateKeyCache.keySet())
        {
            AsymmetricCipherKeyPair sk = privateKeyCache.get(n);
            // -DM Hex.toHexString
            sb.append("    ").append(n.value()).append(" => ")
                    .append(Hex.toHexString(suite.getHPKE().serializePublicKey(sk.getPublic()), 0, 4))
                    .append(Strings.lineSeparator());
        }
        return sb.toString();
    }

    public void truncate(TreeSize size)
    {
        NodeIndex ni = new NodeIndex(new LeafIndex((int)(size.leafCount() - 1)));
        List<NodeIndex> toRemove = new ArrayList<NodeIndex>();
        for (NodeIndex n : pathSecrets.keySet())
        {
            if (n.value() > ni.value())
            {
                toRemove.add(n);
            }
        }

        for (NodeIndex n : toRemove)
        {
            pathSecrets.remove(n);
            privateKeyCache.remove(n);
        }
    }

    public void setLeafKey(byte[] leafSkBytes)
    {
        NodeIndex n = new NodeIndex(index);
        pathSecrets.remove(n);

        AsymmetricCipherKeyPair leafSk = suite.getHPKE().deserializePrivateKey(leafSkBytes, null);
        privateKeyCache.put(n, leafSk);
    }

    public void decap(LeafIndex from, TreeKEMPublicKey pub, byte[] context, UpdatePath path, List<LeafIndex> except)
        throws Exception
    {
        // find decap target
        NodeIndex ni = new NodeIndex(index);
        FilteredDirectPath dp = pub.getFilteredDirectPath(new NodeIndex(from));
        if (dp.parents.size() != path.getNodes().size())
        {
            throw new Exception("Malformed direct path");
        }

        int dpi = 0;
        NodeIndex overlapNode = null;
        ArrayList<NodeIndex> res = new ArrayList<NodeIndex>();
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
        if (res.size() != path.getNodes().get(dpi).getEncryptedPathSecret().size())
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
        AsymmetricCipherKeyPair priv = setPrivateKey(res.get(resi), false);
        HPKECiphertext ct = path.getNodes().get(dpi).getEncryptedPathSecret().get(resi);

        Secret pathSecret = new Secret(suite.decryptWithLabel(
            suite.getHPKE().serializePrivateKey(priv.getPrivate()),
            "UpdatePathNode",
            context,
            ct.getKemOutput(),
            ct.getCiphertext())
        );

        implant(pub, overlapNode, pathSecret);

        if (!consistent(pub))
        {
            throw new Exception("TreeKEMPublicKey inconsistant with TreeKEMPrivateKey");
        }
    }

    private boolean havePrivateKey(NodeIndex n)
    {
        return pathSecrets.containsKey(n) || privateKeyCache.containsKey(n);
    }

    public final boolean consistent(TreeKEMPublicKey other)
        throws IOException
    {
        if (suite.getSuiteID() != other.suite.getSuiteID())
        {
            return false;
        }

        for (NodeIndex node : pathSecrets.keySet())
        {
            setPrivateKey(node, true);
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
            if (!Arrays.equals(pub, suite.getHPKE().serializePublicKey(priv.getPublic())))
            {
                return false;
            }
        }
        return true;
    }

    protected AsymmetricCipherKeyPair setPrivateKey(NodeIndex n, boolean isConst)
        throws IOException
    {
        AsymmetricCipherKeyPair priv = getPrivateKey(n);
        if (priv != null && !isConst)
        {
            privateKeyCache.put(n, priv);
        }
        return priv;
    }

    private AsymmetricCipherKeyPair getPrivateKey(NodeIndex n)
        throws IOException
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

    private void implant(TreeKEMPublicKey pub, NodeIndex start, Secret pathSecret)
        throws Exception
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
        NodeIndex n = index.commonAncestor(to);
        if (!pathSecrets.containsKey(n))
        {
            return new Secret(new byte[0]);
        }
        return pathSecrets.get(n);
    }

}
