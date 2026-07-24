package org.bouncycastle.jcajce.provider.asymmetric.sm9;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.gm.SM9Signature;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.jcajce.provider.util.SecurityExceptions;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.SM9SignPrivateKeyParameters;
import org.bouncycastle.crypto.signers.SM9Signer;

/**
 * JCA {@code SM9} signature (GM/T 0044.2). Sign with the private key from
 * {@link org.bouncycastle.jcajce.interfaces.SM9SignMasterPrivateKey#generateUserKeyPair(byte[])};
 * verify with the signer's public key, formed from the published master public key and
 * the signer's identity via
 * {@link org.bouncycastle.jcajce.interfaces.SM9SignMasterPublicKey#getUserPublicKey(byte[])}.
 * No {@code AlgorithmParameterSpec} is required - the identity travels in the keys.
 */
public class SignatureSpi
    extends java.security.SignatureSpi
{
    private final SM9Signer signer = new SM9Signer();

    private boolean forSigning;
    private SM9SignPrivateKeyParameters signKey;
    private BCSM9SignPublicKey verifyKey;
    private boolean initialised;

    protected void engineInitSign(PrivateKey privateKey)
        throws InvalidKeyException
    {
        if (!(privateKey instanceof BCSM9SignPrivateKey))
        {
            throw new InvalidKeyException(
                "SM9 signing requires the user private key from SM9SignMasterPrivateKey.generateUserKeyPair()");
        }
        forSigning = true;
        signKey = ((BCSM9SignPrivateKey)privateKey).getKeyParameters();
        verifyKey = null;
        initialised = false;
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        if (!(publicKey instanceof BCSM9SignPublicKey))
        {
            throw new InvalidKeyException(
                "SM9 verification requires the signer's public key from SM9SignMasterPublicKey.getUserPublicKey()");
        }
        forSigning = false;
        verifyKey = (BCSM9SignPublicKey)publicKey;
        signKey = null;
        initialised = false;
    }

    protected void engineSetParameter(AlgorithmParameterSpec params)
        throws InvalidAlgorithmParameterException
    {
        throw new InvalidAlgorithmParameterException(
            "SM9 takes no AlgorithmParameterSpec; the signer's identity travels in the key from SM9SignMasterPublicKey.getUserPublicKey()");
    }

    private void ensureInitialised()
    {
        if (initialised)
        {
            return;
        }
        if (forSigning)
        {
            signer.init(true, new ParametersWithRandom(signKey, CryptoServicesRegistrar.getSecureRandom()));
        }
        else
        {
            signer.init(false,
                new ParametersWithID(verifyKey.getMasterPublicKeyParameters(), verifyKey.getIdentity()));
        }
        initialised = true;
    }

    protected void engineUpdate(byte b)
    {
        ensureInitialised();
        signer.update(b);
    }

    protected void engineUpdate(byte[] bytes, int off, int len)
    {
        ensureInitialised();
        signer.update(bytes, off, len);
    }

    protected byte[] engineSign()
        throws SignatureException
    {
        ensureInitialised();
        try
        {
            // the lightweight signer returns the raw components h (32 bytes) || S (uncompressed
            // G1 point); the JCA signature is the GM/T 0080-2020 DER SM9Signature structure.
            byte[] raw = signer.generateSignature();
            return new SM9Signature(Arrays.copyOfRange(raw, 0, 32), Arrays.copyOfRange(raw, 32, raw.length))
                .getEncoded(ASN1Encoding.DER);
        }
        catch (CryptoException e)
        {
            throw SecurityExceptions.signatureException("unable to create SM9 signature: " + e.getMessage(), e);
        }
        catch (IOException e)
        {
            throw SecurityExceptions.signatureException("unable to encode SM9 signature: " + e.getMessage(), e);
        }
    }

    protected boolean engineVerify(byte[] signature)
        throws SignatureException
    {
        ensureInitialised();
        byte[] raw;
        try
        {
            SM9Signature sig = SM9Signature.getInstance(signature);
            raw = Arrays.concatenate(sig.getH(), sig.getS());
        }
        catch (RuntimeException e)
        {
            return false;   // malformed DER - a verifier must reject, not throw
        }
        return signer.verifySignature(raw);
    }

    protected void engineSetParameter(String param, Object value)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    protected Object engineGetParameter(String param)
    {
        throw new UnsupportedOperationException("engineGetParameter unsupported");
    }
}
