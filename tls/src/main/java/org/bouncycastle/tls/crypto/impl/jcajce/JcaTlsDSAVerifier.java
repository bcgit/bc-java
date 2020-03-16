package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.PublicKey;

import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsStreamVerifier;

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

    public TlsStreamVerifier getStreamVerifier(DigitallySigned signature) throws IOException
    {
        SignatureAndHashAlgorithm algorithm = signature.getAlgorithm();

        /*
         * Unfortunately "NoneWithDSA" (a.k.a "RawDSA") only works with 20 byte inputs in the SUN
         * provider. Therefore we need to use a stream signer for other cases.
         * 
         * TODO We could do a test run for raw DSA support of other sizes and then resort to the
         * stream signer only when the provider doesn't support wider hashes.
         */
        if (null != algorithm
            && algorithmType == algorithm.getSignature()
            && HashAlgorithm.getOutputSize(algorithm.getHash()) != 20)
        {
            return crypto.createStreamVerifier(signature, publicKey);
        }

        return null;
    }
}
