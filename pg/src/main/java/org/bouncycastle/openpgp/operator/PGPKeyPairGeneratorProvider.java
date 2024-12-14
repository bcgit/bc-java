package org.bouncycastle.openpgp.operator;

import java.util.Date;

public abstract class PGPKeyPairGeneratorProvider
{
    public abstract PGPKeyPairGenerator get(int version, Date creationTime);
}
