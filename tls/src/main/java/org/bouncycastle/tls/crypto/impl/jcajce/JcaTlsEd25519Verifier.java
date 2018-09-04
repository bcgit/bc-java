package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.PublicKey;

import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.tls.SignatureAlgorithm;

public class JcaTlsEd25519Verifier
    extends JcaTlsEdDSAVerifier
{
    public JcaTlsEd25519Verifier(JcaTlsCrypto crypto, PublicKey publicKey)
    {
        super(crypto, publicKey, SignatureAlgorithm.ed25519, EdECObjectIdentifiers.id_Ed25519);
    }
}
