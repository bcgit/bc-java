package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.PrivateKey;

import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.TlsContext;

public class JcaTlsECDSASigner
    extends JcaTlsDSSSigner
{
    public JcaTlsECDSASigner(TlsContext context, PrivateKey privateKey)
    {
        super(context, privateKey, SignatureAlgorithm.ecdsa, "NoneWithECDSA");
    }
}
