package org.bouncycastle.openpgp.wot.key;

import java.io.File;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import org.bouncycastle.openpgp.PGPSignature;

/**
 * Registry providing fast access to the keys of a public and a secret key ring collection.
 * <p>
 * A {@code PgpKeyRegistry} reads the {@code pubring.gpg} and {@code secring.gpg} (normally located in
 * {@code ~/.gnupg/}) and organizes them in {@link PgpKey} instances. It then provides fast lookup by key-id or
 * fingerprint via {@link #getPgpKey(PgpKeyId)} or {@link #getPgpKey(PgpKeyFingerprint)}.
 * <p>
 * The {@code PgpKeyRegistry} tracks the timestamps of the key ring collection files. If one of the files changes, i.e.
 * the timestamp changes, the files are re-loaded. But beware: The file system's timestamps usually have a pretty bad
 * resolution (of 1 or even 2 seconds). Therefore, it may happen that a modification goes undetected, if multiple
 * changes occur within the resolution.
 */
public interface PgpKeyRegistry
{
    /**
     * Utility class for creating an instance of a {@code PgpKeyRegistry} implementation.
     */
    public static class Helper {
        /**
         * Creates a new instance of a {@code PgpKeyRegistry} implementation.
         * <p>
         * There is currently only one single implementation available ({@code PgpKeyRegistryImpl}),
         * but this might change in the future. Hence, this method should be used instead of
         * directly invoking a constructor!
         * @param pubringFile
         *            the file containing the public keys - usually named {@code pubring.gpg} (located in {@code ~/.gnupg/}
         *            ). Must not be <code>null</code>. The file does not need to exist, though.
         * @param secringFile
         *            the file containing the secret keys - usually named {@code secring.gpg} (located in {@code ~/.gnupg/}
         *            ). Must not be <code>null</code>. The file does not need to exist, though.
         * @return a new instance of a {@code PgpKeyRegistry}. Never <code>null</code>.
         */
        public static PgpKeyRegistry createInstance(final File pubringFile, final File secringFile) {
            return new PgpKeyRegistryImpl(pubringFile, secringFile);
        }
    }

    /**
     * Gets the file containing the public keys - usually named {@code pubring.gpg} (located in {@code ~/.gnupg/}).
     *
     * @return the file containing the public keys. Never <code>null</code>.
     */
    File getPubringFile();

    /**
     * Gets the file containing the secret keys - usually named {@code secring.gpg} (located in {@code ~/.gnupg/}).
     *
     * @return the file containing the secret keys. Never <code>null</code>.
     */
    File getSecringFile();

    /**
     * Gets the key with the given ID. If no such key exists, an {@link IllegalArgumentException} is thrown.
     * <p>
     * It makes no difference to this method whether the key is a master-key or a sub-key.
     *
     * @param pgpKeyId
     *            the key's ID. Must not be <code>null</code>.
     * @return the key identified by the given {@code pgpKeyId}. Never <code>null</code>.
     * @throws IllegalArgumentException
     *             if the given {@code pgpKeyId} is <code>null</code> or there is no key known with this ID.
     */
    PgpKey getPgpKeyOrFail(PgpKeyId pgpKeyId) throws IllegalArgumentException;

    /**
     * Gets the key with the given ID. If no such key exists, <code>null</code> is returned.
     * <p>
     * It makes no difference to this method whether the key is a master-key or a sub-key.
     *
     * @param pgpKeyId
     *            the key's ID. Must not be <code>null</code>.
     * @return the key identified by the given {@code pgpKeyId}. May be <code>null</code>.
     * @throws IllegalArgumentException
     *             if the given {@code pgpKeyId} is <code>null</code>.
     */
    PgpKey getPgpKey(PgpKeyId pgpKeyId) throws IllegalArgumentException;

    /**
     * Gets the key with the given fingerprint. If no such key exists, an {@link IllegalArgumentException} is thrown.
     * <p>
     * It makes no difference to this method whether the key is a master-key or a sub-key.
     *
     * @param pgpKeyFingerprint
     *            the key's fingerprint. Must not be <code>null</code>.
     * @return the key identified by the given {@code pgpKeyFingerprint}. Never <code>null</code>.
     * @throws IllegalArgumentException
     *             if the given {@code pgpKeyFingerprint} is <code>null</code> or there is no key known with this
     *             fingerprint.
     */
    PgpKey getPgpKeyOrFail(PgpKeyFingerprint pgpKeyFingerprint) throws IllegalArgumentException;

    /**
     * Gets the key with the given fingerprint. If no such key exists, <code>null</code> is returned.
     * <p>
     * It makes no difference to this method whether the key is a master-key or a sub-key.
     *
     * @param pgpKeyFingerprint
     *            the key's fingerprint. Must not be <code>null</code>.
     * @return the key identified by the given {@code pgpKeyFingerprint}. May be <code>null</code>.
     * @throws IllegalArgumentException
     *             if the given {@code pgpKeyFingerprint} is <code>null</code>.
     */
    PgpKey getPgpKey(PgpKeyFingerprint pgpKeyFingerprint) throws IllegalArgumentException;

    /**
     * Gets all master-keys. Their sub-keys are accessible via {@link PgpKey#getSubKeys()}.
     *
     * @return all master-keys. Never <code>null</code>.
     */
    Collection<PgpKey> getMasterKeys();

    /**
     * Marks this registry stale - causing it to reload at the next read access.
     * <p>
     * If a modification of a key ring file happens, this modification is usually detected automatically, rendering this
     * registry stale implicitly. However, a change is not reliably detected, because the file system's timestamp
     * resolution is usually 1 second or even worse. Multiple changes within this resolution might thus go undetected.
     * In order to make sure that a key ring file modification reliably causes this registry to reload, this method can
     * be invoked.
     */
    void markStale();

    /**
     * Gets all those keys' fingerprints whose keys were signed (certified) by the key identified by the given
     * fingerprint.
     * <p>
     * Usually, the fingerprint specified should identify a master-key and usually only master-key-fingerprints are
     * returned by this method.
     *
     * @param signingPgpKeyFingerprint
     *            the fingerprint of the key having signed all those keys that we're interested in. Must not be
     *            <code>null</code>.
     * @return the fingerprints of all those keys which have been signed (certified) by the key identified by
     *         {@code signingPgpKeyFingerprint}. Never <code>null</code>, but maybe empty.
     */
    Set<PgpKeyFingerprint> getPgpKeyFingerprintsSignedBy(
            PgpKeyFingerprint signingPgpKeyFingerprint);

    /**
     * Gets all those keys' IDs whose keys were signed (certified) by the key identified by the given ID.
     * <p>
     * Usually, the ID specified should identify a master-key and usually only master-key-IDs are returned by this
     * method.
     *
     * @param signingPgpKeyId
     *            the ID of the key having signed all those keys that we're interested in. Must not be <code>null</code>
     *            .
     * @return the IDs of all those keys which have been signed (certified) by the key identified by
     *         {@code signingPgpKeyId}. Never <code>null</code>, but maybe empty.
     */
    Set<PgpKeyId> getPgpKeyIdsSignedBy(PgpKeyId signingPgpKeyId);

    /**
     * Gets the signatures certifying the authenticity of the given user-ID.
     *
     * @param pgpUserId
     *            the user-ID whose certifications should be returned. Must not be <code>null</code>.
     * @return the certifications authenticating the given {@code pgpUserId}. Never <code>null</code>. Because every
     *         user-ID is normally at least signed by the owning key, it is normally never empty, too.
     */
    List<PGPSignature> getSignatures(PgpUserId pgpUserId);

    /**
     * Determines whether the given signature is a certification.
     * <p>
     * A certification is a signature indicating that a certain key or user-identity is authentic.
     *
     * @param pgpSignature
     *            the signature to be checked. Must not be <code>null</code>.
     * @return <code>true</code>, if the signature is a certification; <code>false</code>, if it is of a different type.
     * @see #isCertification(int)
     */
    boolean isCertification(PGPSignature pgpSignature);

    /**
     * Determines whether the given signature-type indicates a certification.
     * <p>
     * A certification is a signature indicating that a certain key or user-identity is authentic.
     *
     * @param pgpSignatureType
     *            the type of the signature - like {@link PGPSignature#DEFAULT_CERTIFICATION} or other constants (used
     *            by the property {@link PGPSignature#getSignatureType()}, for example).
     * @return <code>true</code>, if the given signature-type means certification; <code>false</code> otherwise.
     * @see #isCertification(PGPSignature)
     */
    boolean isCertification(int pgpSignatureType);
}