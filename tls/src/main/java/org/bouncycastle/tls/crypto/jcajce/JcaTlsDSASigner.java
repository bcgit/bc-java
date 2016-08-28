package org.bouncycastle.tls.crypto.jcajce;

import java.security.PrivateKey;

import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.TlsContext;

public class JcaTlsDSASigner
    extends JcaTlsDSSSigner
{
    public JcaTlsDSASigner(TlsContext context, PrivateKey privateKey)
    {
        super(context, privateKey, SignatureAlgorithm.dsa, "NoneWithDSA");
    }
}
