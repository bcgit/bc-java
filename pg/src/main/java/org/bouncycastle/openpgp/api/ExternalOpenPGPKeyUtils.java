package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.bcpg.PublicSubkeyPacket;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.bcpg.SecretSubkeyPacket;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.api.OpenPGPKey.OpenPGPSecretKey;

import java.util.ArrayList;
import java.util.List;

/**
 * Utility class for converting OpenPGP keys to external keys.
 * Some methods expect a boolean "bestEffort", whose value has the following meaning:
 * <ul>
 *     <li>true: Applications shall use a best-effort method to find the external device carrying the key.</li>
 *     <li>false: Secret key material is marked as unavailable.</li>
 * </ul>
 */
public class ExternalOpenPGPKeyUtils
{
    private final OpenPGPImplementation implementation;

    public ExternalOpenPGPKeyUtils(OpenPGPImplementation implementation)
    {
        this.implementation = implementation;
    }

    /**
     * Turn an {@link OpenPGPCertificate} into an external {@link OpenPGPKey} with all component keys
     * changed into external secret keys with "best-effort" locator hint.
     *
     * @param certificate certificate
     * @return external key
     */
    public OpenPGPKey fromCertificate(OpenPGPCertificate certificate)
    {
        return fromCertificate(certificate, true);
    }

    /**
     * Turn an {@link OpenPGPCertificate} into an external {@link OpenPGPKey} with all component keys
     * changed into external secret keys.
     * If <pre>bestEffort</pre> is <pre>true</pre> all keys are marked with the best-effort locator hint.
     * If <pre>bestEffort</pre> is <pre>false</pre> the keys are marked as unavailable.
     *
     * @param certificate certificate
     * @param bestEffort best-effort if true, unavailable otherwise
     * @return external key
     */
    public OpenPGPKey fromCertificate(OpenPGPCertificate certificate, boolean bestEffort)
    {
        return fromCertificate(certificate, hint(bestEffort));
    }

    /**
     * Turn an {@link OpenPGPCertificate} into an external {@link OpenPGPKey} with all component keys
     * changed into external secret keys.
     * All component keys will carry the passed in <pre>locatorHint</pre>.
     *
     * @param certificate certificate
     * @param locatorHint locator hint encoding
     * @return external key
     */
    public OpenPGPKey fromCertificate(OpenPGPCertificate certificate, byte[] locatorHint)
    {
        List<PGPSecretKey> keys = new ArrayList<>();
        for (OpenPGPCertificate.OpenPGPComponentKey componentKey : certificate.getKeys())
        {
            PGPPublicKey publicKey = componentKey.getPGPPublicKey();
            keys.add(toExternalKey(publicKey, locatorHint));
        }

        return new OpenPGPKey(new PGPSecretKeyRing(keys), implementation);
    }

    /**
     * Turn an {@link OpenPGPKey} into an external {@link OpenPGPKey}, marking all component keys
     * with the "best-effort" locator hint.
     *
     * @param key OpenPGP key
     * @return external OpenPGP key
     */
    public OpenPGPKey toExternalKey(OpenPGPKey key)
    {
        return toExternalKey(key, true);
    }

    /**
     * Turn an {@link OpenPGPKey} into an external {@link OpenPGPKey}.
     * If <pre>bestEffort</pre> is <pre>true</pre> all keys are marked with the best-effort locator hint.
     * If <pre>bestEffort</pre> is <pre>false</pre> the keys are marked as unavailable.
     *
     * @param key OpenPGP key
     * @param bestEffort best-effort if true, unavailable otherwise
     * @return external OpenPGP key
     */
    public OpenPGPKey toExternalKey(OpenPGPKey key, boolean bestEffort)
    {
        return toExternalKey(key, hint(bestEffort));
    }

    /**
     * Turn an {@link OpenPGPKey} into an external {@link OpenPGPKey}.
     * All component keys will carry the passed-in <pre>locatorHint</pre>.
     *
     * @param key OpenPGP key
     * @param locatorHint locator hint encoding
     * @return external OpenPGP key
     */
    public OpenPGPKey toExternalKey(OpenPGPKey key, byte[] locatorHint)
    {
        List<OpenPGPSecretKey> secretKeys = new ArrayList<>();
        for (OpenPGPSecretKey sk : key.getSecretKeys().values())
        {
            secretKeys.add(new OpenPGPSecretKey(
                    sk.getPublicKey(),
                    toExternalKey(sk.getPGPSecretKey(), locatorHint),
                    implementation.pbeSecretKeyDecryptorBuilderProvider()));
        }
        return new OpenPGPKey(secretKeys, implementation);
    }

    /**
     * Turn a single {@link OpenPGPSecretKey} into an external {@link OpenPGPSecretKey}.
     * If <pre>bestEffort</pre> is <pre>true</pre> the key is marked with the best-effort locator hint.
     * If <pre>bestEffort</pre> is <pre>false</pre> the key is marked as unavailable.
     *
     * @param key secret key
     * @param bestEffort best-effort if true, unavailable otherwise
     * @return external secret key
     */
    public OpenPGPSecretKey toExternalKey(OpenPGPSecretKey key, boolean bestEffort)
    {
        return toExternalKey(key, hint(bestEffort));
    }

    /**
     * Turn a single {@link OpenPGPSecretKey} into an external {@link OpenPGPSecretKey}.
     * The key will carry the passed-in <pre>locatorHint</pre>.
     *
     * @param key secret key
     * @param locatorHint locator hint encoding
     * @return external secret key
     */
    public OpenPGPSecretKey toExternalKey(OpenPGPSecretKey key, byte[] locatorHint)
    {
        PGPSecretKey externalKey = toExternalKey(key.getPGPSecretKey(), locatorHint);
        return new OpenPGPSecretKey(key.getPublicKey(), externalKey, implementation.pbeSecretKeyDecryptorBuilderProvider());
    }

    /**
     * Turn a single component key within the passed in {@link OpenPGPKey} into an external key, marking it
     * with a "best-effort" locator hint.
     *
     * @param key OpenPGP key
     * @param componentKey identifier of the component key that shall be marked as external
     * @return OpenPGP key with the identified component key marked as external
     */
    public OpenPGPKey toExternalKey(OpenPGPKey key, KeyIdentifier componentKey)
    {
        return toExternalKey(key, componentKey, true);
    }

    /**
     * Turn a single component key within the passed in {@link OpenPGPKey} into an external key.
     * If <pre>bestEffort</pre> is <pre>true</pre> the key is marked with the best-effort locator hint.
     * If <pre>bestEffort</pre> is <pre>false</pre> the key is marked as unavailable.
     *
     * @param key OpenPGP key
     * @param componentKey identifier of the component key that shall be marked as external
     * @param bestEffort best-effort if true, unavailable otherwise
     * @return OpenPGP key with the identified component key marked as external
     */
    public OpenPGPKey toExternalKey(OpenPGPKey key, KeyIdentifier componentKey, boolean bestEffort)
    {
        return toExternalKey(key, componentKey, hint(bestEffort));
    }

    /**
     * Turn a single component key within the passed in {@link OpenPGPKey} into an external key.
     * The component key will carry the passed in <pre>locatorHint</pre>.
     *
     * @param key OpenPGP key
     * @param componentKey identifier of the component key that shall be marked as external
     * @param locatorHint locator hint encoding
     * @return OpenPGP key with the identified component key marked as external
     */
    public OpenPGPKey toExternalKey(OpenPGPKey key, KeyIdentifier componentKey, byte[] locatorHint)
    {
        List<OpenPGPSecretKey> secretKeys = new ArrayList<>();
        for (OpenPGPSecretKey sk : key.getSecretKeys().values())
        {
            if (sk.getKeyIdentifier().matchesExplicit(componentKey))
            {
                secretKeys.add(new OpenPGPSecretKey(
                        sk.getPublicKey(),
                        toExternalKey(sk.getPGPSecretKey(), locatorHint),
                        implementation.pbeSecretKeyDecryptorBuilderProvider()));
            }
            else
            {
                secretKeys.add(sk);
            }
        }
        return new OpenPGPKey(secretKeys, implementation);
    }

    /**
     * Turn a single {@link PGPSecretKey} into an external {@link PGPSecretKey}.
     * If <pre>bestEffort</pre> is <pre>true</pre> the key is marked with the best-effort locator hint.
     * If <pre>bestEffort</pre> is <pre>false</pre> the key is marked as unavailable.
     *
     * @param secretKey secret key
     * @param bestEffort best-effort if true, unavailable otherwise
     * @return external secret key
     */
    public static PGPSecretKey toExternalKey(PGPSecretKey secretKey, boolean bestEffort)
    {
        return toExternalKey(secretKey, hint(bestEffort));
    }

    /**
     * Turn a single {@link PGPSecretKey} into an external {@link PGPSecretKey}.
     * The key will carry the passed-in <pre>locatorHint</pre>.
     *
     * @param secretKey secret key
     * @param locatorHint locator hint encoding
     * @return external secret key
     */
    public static PGPSecretKey toExternalKey(PGPSecretKey secretKey, byte[] locatorHint)
    {
        return toExternalKey(secretKey.getPublicKey(), locatorHint);
    }

    /**
     * Turn a single {@link PGPPublicKey} into an external {@link PGPSecretKey}.
     * If <pre>bestEffort</pre> is <pre>true</pre> the key is marked with the best-effort locator hint.
     * If <pre>bestEffort</pre> is <pre>false</pre> the key is marked as unavailable.
     *
     * @param publicKey public key
     * @param bestEffort best-effort if true, unavailable otherwise
     * @return external secret key
     */
    public static PGPSecretKey toExternalKey(PGPPublicKey publicKey, boolean bestEffort)
    {
        return toExternalKey(publicKey, hint(bestEffort));
    }

    /**
     * Turn a single {@link PGPPublicKey} into an external {@link PGPSecretKey}.
     * The key will carry the passed-in <pre>locatorHint</pre>.
     *
     * @param publicKey public key
     * @param locatorHint locator hint encoding
     * @return external secret key
     */
    public static PGPSecretKey toExternalKey(PGPPublicKey publicKey, byte[] locatorHint)
    {
        if (publicKey.isMasterKey())
        {
            return new PGPSecretKey(
                    new SecretKeyPacket(
                            publicKey.getPublicKeyPacket(),
                            locatorHint),
                    publicKey);
        }
        else
        {
            return new PGPSecretKey(
                    new SecretSubkeyPacket(
                            (PublicSubkeyPacket) publicKey.getPublicKeyPacket(),
                            locatorHint),
                    publicKey);
        }
    }

    private static byte[] hint(boolean bestEffort)
    {
        if (bestEffort)
        {
            // Best Effort
            return new byte[]{0};
        }
        // Unavailable
        return new byte[0];
    }
}
