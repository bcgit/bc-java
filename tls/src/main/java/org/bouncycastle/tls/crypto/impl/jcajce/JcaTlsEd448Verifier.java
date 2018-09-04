package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.PublicKey;

import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.tls.SignatureAlgorithm;

public class JcaTlsEd448Verifier
    extends JcaTlsEdDSAVerifier
{
    public JcaTlsEd448Verifier(JcaTlsCrypto crypto, PublicKey publicKey)
    {
        super(crypto, publicKey, SignatureAlgorithm.ed448, EdECObjectIdentifiers.id_Ed448);
    }
}
