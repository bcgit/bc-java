package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.crypto.TlsStreamVerifier;
import org.bouncycastle.tls.crypto.TlsVerifier;

/**
 * Operator supporting the verification of RSASSA-PSS signatures.
 */
public class JcaTlsRSAPSSVerifier
    implements TlsVerifier
{
    private final JcaTlsCrypto crypto;
    private final PublicKey publicKey;
    private final int signatureScheme;

    public JcaTlsRSAPSSVerifier(JcaTlsCrypto crypto, PublicKey publicKey, int signatureScheme)
    {
        if (null == crypto)
        {
            throw new NullPointerException("crypto");
        }
        if (null == publicKey)
        {
            throw new NullPointerException("publicKey");
        }
        if (!SignatureScheme.isRSAPSS(signatureScheme))
        {
            throw new IllegalArgumentException("signatureScheme");
        }

        this.crypto = crypto;
        this.publicKey = publicKey;
        this.signatureScheme = signatureScheme;
    }

    public boolean verifyRawSignature(DigitallySigned digitallySigned, byte[] hash) throws IOException
    {
        throw new UnsupportedOperationException();

        // TODO Can only use this if "NoneWithRSASSA-PSS" is available
//        SignatureAndHashAlgorithm algorithm = digitallySigned.getAlgorithm();
//        if (algorithm == null || SignatureScheme.from(algorithm) != signatureScheme)
//        {
//            throw new IllegalStateException("Invalid algorithm: " + algorithm);
//        }
//
//        int cryptoHashAlgorithm = SignatureScheme.getCryptoHashAlgorithm(signatureScheme);
//        String digestName = crypto.getDigestName(cryptoHashAlgorithm);
//
//        // NOTE: We explicitly set them even though they should be the defaults, because providers vary
//        AlgorithmParameterSpec pssSpec = RSAUtil.getPSSParameterSpec(cryptoHashAlgorithm, digestName,
//            crypto.getHelper());
//
//        try
//        {
//            Signature verifier = crypto.getHelper().createSignature("NoneWithRSASSA-PSS");
//            verifier.setParameter(pssSpec);
//            verifier.initVerify(publicKey);
//            verifier.update(hash);
//            return verifier.verify(digitallySigned.getSignature());
//        }
//        catch (GeneralSecurityException e)
//        {
//            throw new TlsFatalAlert(AlertDescription.internal_error, e);
//        }
    }

    public TlsStreamVerifier getStreamVerifier(DigitallySigned digitallySigned) throws IOException
    {
        SignatureAndHashAlgorithm algorithm = digitallySigned.getAlgorithm();
        if (algorithm == null || SignatureScheme.from(algorithm) != signatureScheme)
        {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        int cryptoHashAlgorithm = SignatureScheme.getCryptoHashAlgorithm(signatureScheme);
        String digestName = crypto.getDigestName(cryptoHashAlgorithm);
        String sigName = RSAUtil.getDigestSigAlgName(digestName) + "WITHRSAANDMGF1";

        // NOTE: We explicitly set them even though they should be the defaults, because providers vary
        AlgorithmParameterSpec pssSpec = RSAUtil.getPSSParameterSpec(cryptoHashAlgorithm, digestName,
            crypto.getHelper());

        return crypto.createStreamVerifier(sigName, pssSpec, digitallySigned.getSignature(), publicKey);
    }
}
