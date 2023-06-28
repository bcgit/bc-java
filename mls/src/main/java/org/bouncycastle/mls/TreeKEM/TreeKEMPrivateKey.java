package org.bouncycastle.mls.TreeKEM;

import org.bouncycastle.mls.crypto.Secret;

import java.util.HashMap;
import java.util.Map;

public class TreeKEMPrivateKey
//    implements MLSInputStream.Readable, MLSOutputStream.Writable

{
    LeafIndex index;
    byte[] updateSecret;
    Map<NodeIndex, Secret> pathSecrets;
    Map<NodeIndex, Secret> privateKeyCache;

    public TreeKEMPrivateKey(LeafIndex index)
    {
        this.index = index;
        pathSecrets = new HashMap<>();
        privateKeyCache = new HashMap<>();
    }

    public static TreeKEMPrivateKey solo(LeafIndex index, Secret leafPriv)
    {
        TreeKEMPrivateKey priv = new TreeKEMPrivateKey(index);
        priv.privateKeyCache.put(new NodeIndex(index), leafPriv);
        return priv;
    }

}
