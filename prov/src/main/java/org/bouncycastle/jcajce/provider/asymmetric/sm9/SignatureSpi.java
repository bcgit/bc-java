package org.bouncycastle.jcajce.provider.asymmetric.sm9;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
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
import org.bouncycastle.crypto.params.SM9SigPrivateKeyParameters;
import org.bouncycastle.crypto.signers.SM9Signer;

/**
 * JCA {@code SM9} signature (GM/T 0044.2). Sign with the private key from
 * {@link org.bouncycastle.jcajce.interfaces.SM9SigMasterPrivateKey#generateUserKeyPair(byte[])};
 * verify with the signer's public key, formed from the published master public key and
 * the signer's identity via
 * {@link org.bouncycastle.jcajce.interfaces.SM9SigMasterPublicKey#getUserPublicKey(byte[])}.
 * No {@code AlgorithmParameterSpec} is required - the identity travels in the keys.
 */
public class SignatureSpi
    extends java.security.SignatureSpi
{
    private final SM9Signer signer = new SM9Signer();

    private boolean forSigning;
    private SM9SigPrivateKeyParameters signKey;
    private SecureRandom signRandom;
    private BCSM9SigPublicKey verifyKey;
    private boolean initialised;

    protected void engineInitSign(PrivateKey privateKey)
        throws InvalidKeyException
    {
        engineInitSign(privateKey, null);
    }

    /**
     * Each init decides afresh where the signing nonce is drawn from: the SecureRandom handed to
     * Signature.initSign(key, random), or the default source for an init given none. The random of
     * initSign(key, random) had been read from the appRandom field java.security.SignatureSpi
     * records it in, which nothing resets, so a later initSign(key) went on drawing from the random
     * of the earlier call.
     */
    protected void engineInitSign(PrivateKey privateKey, SecureRandom random)
        throws InvalidKeyException
    {
        // the previous key is dropped before the new one is examined, so that an init this goes on
        // to refuse leaves the object uninitialised - update(), sign() and verify() then say so -
        // rather than still holding the last key, and the message given under it, for them to use
        uninitialise();

        if (!(privateKey instanceof BCSM9SigPrivateKey))
        {
            throw new InvalidKeyException(
                "SM9 signing requires the user private key from SM9SigMasterPrivateKey.generateUserKeyPair()");
        }
        if (((BCSM9SigPrivateKey)privateKey).isDestroyed())
        {
            // refused here, as the other signature SPIs refuse a destroyed key, rather than taken
            // and left to fail in sign() with an IllegalStateException it does not declare
            throw new InvalidKeyException("key destroyed");
        }
        forSigning = true;
        signKey = ((BCSM9SigPrivateKey)privateKey).getKeyParameters();
        signRandom = random;
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        // as in engineInitSign
        uninitialise();

        if (!(publicKey instanceof BCSM9SigPublicKey))
        {
            throw new InvalidKeyException(
                "SM9 verification requires the signer's public key from SM9SigMasterPublicKey.getUserPublicKey()");
        }
        verifyKey = (BCSM9SigPublicKey)publicKey;
    }

    /**
     * Drop the key the last init installed, and the message given since. java.security.Signature
     * records an init only once it has succeeded, so after one that is refused it goes on passing
     * update(), sign() and verify() here as the init before it allowed; every init starts here, so
     * that they then refuse, as SM9Signer's do after a refused init, rather than run under the
     * last key.
     */
    private void uninitialise()
    {
        forSigning = false;
        signKey = null;
        signRandom = null;
        verifyKey = null;
        initialised = false;
        signer.reset();
    }

    protected void engineSetParameter(AlgorithmParameterSpec params)
        throws InvalidAlgorithmParameterException
    {
        throw new InvalidAlgorithmParameterException(
            "SM9 takes no AlgorithmParameterSpec; the signer's identity travels in the key from SM9SigMasterPublicKey.getUserPublicKey()");
    }

    private void ensureInitialised()
        throws SignatureException
    {
        if (initialised)
        {
            return;
        }
        if (signKey == null && verifyKey == null)
        {
            // an init was refused after the last that succeeded, and dropped that one's key
            throw new SignatureException("SM9 signature not initialised");
        }
        if (forSigning)
        {
            // signRandom is the SecureRandom the last init was handed, if any: the nonce is drawn
            // from it, and from the default source only where the init was given none
            signer.init(true, new ParametersWithRandom(signKey, CryptoServicesRegistrar.getSecureRandom(signRandom)));
        }
        else
        {
            signer.init(false,
                new ParametersWithID(verifyKey.getMasterPublicKeyParameters(), verifyKey.getIdentity()));
        }
        initialised = true;
    }

    protected void engineUpdate(byte b)
        throws SignatureException
    {
        ensureInitialised();
        signer.update(b);
    }

    protected void engineUpdate(byte[] bytes, int off, int len)
        throws SignatureException
    {
        ensureInitialised();
        signer.update(bytes, off, len);
    }

    protected byte[] engineSign()
        throws SignatureException
    {
        ensureInitialised();
        if (signKey != null && signKey.isDestroyed())
        {
            // the key is refused at init; one destroyed since cannot sign, and says so through the
            // exception sign() declares rather than the key's own IllegalStateException
            throw new SignatureException("key destroyed");
        }
        try
        {
            return encodeSignature(signer.generateSignature());
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
        try
        {
            byte[] raw;
            try
            {
                SM9Signature sig = SM9Signature.getInstance(signature);
                raw = Arrays.concatenate(sig.getH(), sig.getS());
                // only the encoding engineSign() gives these components is taken: the parse alone
                // also accepts a non-minimal length, and h and S can trade bytes across their field
                // boundary without changing the h || S the signer is handed
                if (!Arrays.areEqual(encodeSignature(raw), signature))
                {
                    return false;
                }
            }
            catch (IOException e)
            {
                throw SecurityExceptions.signatureException("unable to encode SM9 signature: " + e.getMessage(), e);
            }
            catch (RuntimeException e)
            {
                return false;   // malformed DER - a verifier must reject, not throw
            }
            return signer.verifySignature(raw);
        }
        finally
        {
            // however this method leaves, the accumulated message is consumed and the signature
            // object goes back to the state initVerify left it in, ready for fresh data. On the
            // path through verifySignature() the signer has already reset it, so this is then a no-op.
            signer.reset();
        }
    }

    /**
     * The lightweight signer works with the raw components h (32 bytes) || S (uncompressed G1
     * point); the JCA signature is the GM/T 0080-2020 DER SM9Signature structure.
     */
    private static byte[] encodeSignature(byte[] raw)
        throws IOException
    {
        return new SM9Signature(Arrays.copyOfRange(raw, 0, 32), Arrays.copyOfRange(raw, 32, raw.length))
            .getEncoded(ASN1Encoding.DER);
    }

    protected void engineSetParameter(String param, Object value)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    protected Object engineGetParameter(String param)
    {
        throw new UnsupportedOperationException("engineGetParameter unsupported");
    }

    /**
     * SM9 signing takes no algorithm parameters, so there are none to report. Without this
     * override java.security.SignatureSpi's default threw UnsupportedOperationException out of
     * Signature.getParameters(), where the answer BC gives for a parameterless scheme is null.
     */
    protected AlgorithmParameters engineGetParameters()
    {
        return null;
    }
}
