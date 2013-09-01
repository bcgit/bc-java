package org.bouncycastle.crypto.tls;

import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public abstract class AbstractTlsSigner
    implements TlsSigner
{
    protected TlsContext context;

    public void init(TlsContext context)
    {
        this.context = context;
    }

    public Signer createSigner(AsymmetricKeyParameter privateKey)
    {
        return createSigner(null, privateKey);
    }

    public Signer createVerifyer(AsymmetricKeyParameter publicKey)
    {
        return createVerifyer(null, publicKey);
    }
}
