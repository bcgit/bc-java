package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.PrivateKey;

import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsStreamSigner;

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

    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm)
        throws IOException
    {
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
            return crypto.createStreamSigner(algorithm, privateKey, true);
        }

        return null;
    }
}
