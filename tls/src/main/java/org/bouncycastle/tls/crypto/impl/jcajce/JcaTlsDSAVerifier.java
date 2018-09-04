package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.PublicKey;

import org.bouncycastle.tls.SignatureAlgorithm;

/**
 * Implementation class for the verification of the raw DSA signature type using the JCA.
 */
public class JcaTlsDSAVerifier
    extends JcaTlsDSSVerifier
{
    public JcaTlsDSAVerifier(JcaTlsCrypto crypto, PublicKey publicKey)
    {
        super(crypto, publicKey, SignatureAlgorithm.dsa, "NoneWithDSA");
    }
}
