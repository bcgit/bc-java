package org.bouncycastle.pqc.legacy.crypto.gmss;

import org.bouncycastle.crypto.Digest;

public interface GMSSDigestProvider
{
    Digest get();
}
