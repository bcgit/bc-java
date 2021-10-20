package org.bouncycastle.tls.crypto.impl.bc;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.TlsStreamSigner;

import java.io.IOException;
import java.security.Signature;

/**
 * GMSSL need two certificate
 * one for sign, one for encrypt
 * so we need provider Signer and Decryptor both
 *
 *
 * @since 2021-03-12 12:10:31
 */
public class BcGMSSLCredentials implements TlsCredentialedSigner, TlsCredentialedDecryptor
{
    private BcTlsCrypto crypto;
    /*
     * first cert for sign, second sert for encrypt
     */
    private Certificate certList;

    private AsymmetricKeyParameter signKey;
    private AsymmetricKeyParameter encKey;
    private Signature rawSigner;

    public BcGMSSLCredentials(BcTlsCrypto crypto, Certificate certList, AsymmetricKeyParameter signKey, AsymmetricKeyParameter encKey)
    {
        if(certList.getLength() < 2)
        {
            throw new IllegalArgumentException("GMSSL need two certificate, first one for sign second one for encrypt.");
        }

        this.crypto = crypto;
        this.certList = certList;
        this.signKey = signKey;
        this.encKey = encKey;
    }

    /**
     * Use encrypt key decrypt ciphertext
     *
     * @param cryptoParams the parameters to use for the decryption.
     * @param ciphertext   the cipher text containing the secret.
     * @return
     * @throws IOException
     */
    public TlsSecret decrypt(TlsCryptoParameters cryptoParams, byte[] ciphertext) throws IOException
    {
        try
        {
            // Parser ciphertext as ASN.1 SM2Cipher object.
            final SM2Cipher sm2Cipher = SM2Cipher.getInstance(ciphertext);
            byte[] c1c3c2 = sm2Cipher.convertC1C3C2();
            SM2Engine engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
            engine.init(false, encKey);
            byte[] preMasterSecret = engine.processBlock(c1c3c2, 0, c1c3c2.length);
            return new BcTlsSecret(crypto, preMasterSecret);
        } catch (Exception e)
        {
            throw new TlsFatalAlertReceived(AlertDescription.illegal_parameter);
        }
    }

    /**
     * Use sign private key sign
     *
     * @param hash a message digest calculated across the message the signature is to apply to.
     * @return signature
     * @throws IOException
     */
    public byte[] generateRawSignature(byte[] hash) throws IOException
    {
        try
        {
            final ParametersWithRandom prvKey = new ParametersWithRandom(signKey, crypto.getSecureRandom());
            SM2Signer sm2Signer = new SM2Signer();
            sm2Signer.init(true, prvKey);
            sm2Signer.update(hash, 0, hash.length);
            return sm2Signer.generateSignature();
        }
        catch (CryptoException e)
        {
            e.printStackTrace();
            throw new TlsFatalAlertReceived(AlertDescription.illegal_parameter);
        }
    }

    public SignatureAndHashAlgorithm getSignatureAndHashAlgorithm()
    {
        return SignatureAndHashAlgorithm.sm2;
    }


    /**
     * GMSSL not support Stream mode
     *
     * @return null
     * @throws IOException not happen
     */
    public TlsStreamSigner getStreamSigner() throws IOException
    {
        return null;
    }

    public Certificate getCertificate()
    {
        return certList;
    }
}
