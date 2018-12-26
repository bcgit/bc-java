package org.bouncycastle.pqc.crypto.xmss;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class XMSSMTKeyParameters
    extends AsymmetricKeyParameter
{
    private final String treeDigest;

    public XMSSMTKeyParameters(boolean isPrivateKey, String treeDigest)
    {
        super(isPrivateKey);
        this.treeDigest = treeDigest;
    }

    public String getTreeDigest()
    {
        return treeDigest;
    }
}
