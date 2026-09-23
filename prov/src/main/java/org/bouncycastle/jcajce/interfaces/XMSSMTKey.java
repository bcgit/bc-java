package org.bouncycastle.jcajce.interfaces;

public interface XMSSMTKey
{
    int getHeight();

    int getLayers();

    String getTreeDigest();
}
