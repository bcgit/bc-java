package org.bouncycastle.jcajce.provider.asymmetric.util;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.SignatureSpi;

/**
 * Base for signature services whose signing draws on a SecureRandom. Each initSign decides afresh where that
 * randomness comes from: the SecureRandom passed to initSign(key, random), or the default source for an
 * initSign(key) given none. Signature.initSign(key) calls engineInitSign(key) only, so without this a SecureRandom
 * kept from an earlier initSign(key, random) would go on being used in place of the default.
 * <p>
 * As with the JDK's own SignatureSpi, engineInitSign(key, random) stores the SecureRandom in appRandom and calls
 * engineInitSign(key), so a subclass overriding engineInitSign(key) still sees both forms of initSign. The work is
 * done in {@link #signInit(PrivateKey, SecureRandom)}, which is given appRandom (null for the default source).
 * Keep this class in step with {@link BaseInitRandomSignature}, its twin for services extending
 * java.security.Signature.
 * </p>
 */
public abstract class BaseInitRandomSignatureSpi
    extends SignatureSpi
{
    private boolean randomGiven = false;

    protected BaseInitRandomSignatureSpi()
    {
    }

    protected void engineInitSign(
        PrivateKey privateKey,
        SecureRandom random)
        throws InvalidKeyException
    {
        appRandom = random;
        randomGiven = true;
        try
        {
            engineInitSign(privateKey);
        }
        finally
        {
            randomGiven = false;
        }
    }

    protected void engineInitSign(
        PrivateKey privateKey)
        throws InvalidKeyException
    {
        if (!randomGiven)
        {
            appRandom = null;
        }

        signInit(privateKey, appRandom);
    }

    /**
     * Initialise for signing.
     *
     * @param privateKey the signing key.
     * @param random the SecureRandom to sign with, or null for the default source.
     * @throws InvalidKeyException if the key is unsuitable.
     */
    protected abstract void signInit(PrivateKey privateKey, SecureRandom random)
        throws InvalidKeyException;
}
