package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.PrivateKey;

import org.bouncycastle.tls.SignatureAlgorithm;

/**
 * Implementation class for generation of the raw DSA signature type using the JCA.
 */
public class JcaTlsDSASigner
    extends JcaTlsDSSSigner
{
    public JcaTlsDSASigner(JcaTlsCrypto crypto, PrivateKey privateKey)
    {
        super(crypto, privateKey, SignatureAlgorithm.dsa, "NoneWithDSA");
    }
}
