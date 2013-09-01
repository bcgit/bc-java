package org.bouncycastle.crypto.tls;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.GenericSigner;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.util.Arrays;

public class TlsRSASigner
    extends AbstractTlsSigner
{
    public byte[] generateRawSignature(AsymmetricKeyParameter privateKey, byte[] md5AndSha1)
        throws CryptoException
    {
        AsymmetricBlockCipher engine = createRSAImpl();
        engine.init(true, new ParametersWithRandom(privateKey, this.context.getSecureRandom()));
        return engine.processBlock(md5AndSha1, 0, md5AndSha1.length);
    }

    public boolean verifyRawSignature(byte[] sigBytes, AsymmetricKeyParameter publicKey, byte[] md5AndSha1)
        throws CryptoException
    {
        AsymmetricBlockCipher engine = createRSAImpl();
        engine.init(false, publicKey);
        byte[] signed = engine.processBlock(sigBytes, 0, sigBytes.length);
        return Arrays.constantTimeAreEqual(signed, md5AndSha1);
    }

    public Signer createSigner(SignatureAndHashAlgorithm algorithm, AsymmetricKeyParameter privateKey)
    {
        return makeSigner(algorithm, true, new ParametersWithRandom(privateKey, this.context.getSecureRandom()));
    }

    public Signer createVerifyer(SignatureAndHashAlgorithm algorithm, AsymmetricKeyParameter publicKey)
    {
        return makeSigner(algorithm, false, publicKey);
    }

    public boolean isValidPublicKey(AsymmetricKeyParameter publicKey)
    {
        return publicKey instanceof RSAKeyParameters && !publicKey.isPrivate();
    }

    protected Signer makeSigner(SignatureAndHashAlgorithm algorithm, boolean forSigning, CipherParameters cp)
    {
        Digest d;
        if (algorithm == null)
        {
            d = new CombinedHash();
        }
        else
        {
            if (algorithm.getSignature() != SignatureAlgorithm.rsa)
            {
                throw new IllegalStateException();
            }

            d = TlsUtils.createHash(algorithm.getHash());
        }

        return makeSigner(d, false, cp);
    }

    protected Signer makeSigner(Digest d, boolean forSigning, CipherParameters cp)
    {
        Signer s;
        if (TlsUtils.isTLSv12(context))
        {
            /*
             * RFC 5246 4.7. In RSA signing, the opaque vector contains the signature generated
             * using the RSASSA-PKCS1-v1_5 signature scheme defined in [PKCS1].
             */
            s = new RSADigestSigner(d);
        }
        else
        {
            /*
             * RFC 5246 4.7. Note that earlier versions of TLS used a different RSA signature scheme
             * that did not include a DigestInfo encoding.
             */
            s = new GenericSigner(createRSAImpl(), d);
        }
        s.init(forSigning, cp);
        return s;
    }

    protected AsymmetricBlockCipher createRSAImpl()
    {
        /*
         * RFC 5264 7.4.7.1. Implementation note: It is now known that remote timing-based attacks
         * on TLS are possible, at least when the client and server are on the same LAN.
         * Accordingly, implementations that use static RSA keys MUST use RSA blinding or some other
         * anti-timing technique, as described in [TIMING].
         */
        return new PKCS1Encoding(new RSABlindedEngine());
    }
}
