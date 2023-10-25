package org.bouncycastle.tls.injection.signaturespi;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.tls.injection.sigalgs.PrivateKeyToCipherParameters;
import org.bouncycastle.tls.injection.sigalgs.PublicKeyToCipherParameters;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class UniversalSignatureSpi
        extends java.security.SignatureSpi {
    private final Digest digest;
    private final MessageSigner signer;


    private PublicKeyToCipherParameters pkToParams;
    private PrivateKeyToCipherParameters skToParams;

    public UniversalSignatureSpi(Digest digest, MessageSigner signer,
                                 PublicKeyToCipherParameters pkToParams,
                                 PrivateKeyToCipherParameters skToParams) {
        this.digest = digest;
        this.signer = signer;
        this.pkToParams = pkToParams;
        this.skToParams = skToParams;
    }

    protected void engineInitVerify(PublicKey publicKey)
            throws InvalidKeyException {
        CipherParameters params = this.pkToParams.parameters(publicKey);
        signer.init(false, params);
    }

    protected void engineInitSign(PrivateKey privateKey, SecureRandom random)
            throws InvalidKeyException {
        this.appRandom = random;
        engineInitSign(privateKey);
    }

    protected void engineInitSign(PrivateKey privateKey)
            throws InvalidKeyException {
        CipherParameters params = this.skToParams.parameters(privateKey);
        signer.init(false, params);


        if (appRandom != null) {
            signer.init(true, new ParametersWithRandom(params, appRandom));
        } else {
            signer.init(true, params);
        }
    }

    protected void engineUpdate(byte b)
            throws SignatureException {
        digest.update(b);
    }

    protected void engineUpdate(byte[] b, int off, int len)
            throws SignatureException {
        digest.update(b, off, len);
    }

    protected byte[] engineSign()
            throws SignatureException {
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        try {
            byte[] sig = signer.generateSignature(hash);

            return sig;
        } catch (Exception e) {
            throw new SignatureException(e.toString());
        }
    }

    protected boolean engineVerify(byte[] sigBytes)
            throws SignatureException {
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);

        boolean result = signer.verifySignature(hash, sigBytes);
        return result;
    }

    protected void engineSetParameter(AlgorithmParameterSpec params) {
        // TODO
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    /**
     * @deprecated replaced with #engineSetParameter(java.security.spec.AlgorithmParameterSpec)
     */
    protected void engineSetParameter(String param, Object value) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    /**
     * @deprecated
     */
    protected Object engineGetParameter(String param) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

}

