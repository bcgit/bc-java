package org.bouncycastle.openpgp.wot;

import static org.bouncycastle.openpgp.wot.internal.Util.*;

import java.io.File;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.wot.internal.TrustDbImpl;
import org.bouncycastle.openpgp.wot.key.PgpKey;
import org.bouncycastle.openpgp.wot.key.PgpKeyRegistry;
import org.bouncycastle.openpgp.wot.key.PgpUserId;
import org.bouncycastle.openpgp.wot.key.PgpUserIdNameHash;

/**
 * API for working with <a href="https://gnupg.org/">GnuPG</a>'s {@code trustdb.gpg}.
 * <p>
 * An instance is used for the following purposes:
 * <ul>
 * <li>Read the validity of a {@linkplain #getValidityRaw(PGPPublicKey) certain key},
 * {@linkplain #getValidityRaw(PGPPublicKey, PgpUserIdNameHash) user-identity or user-attribute}.
 * <li>Find out whether a key is {@linkplain #isDisabled(PGPPublicKey) disabled}.
 * <li>Mark a key {@linkplain #setDisabled(PGPPublicKey, boolean) disabled} or enabled.
 * <li>Set a key's {@linkplain #setOwnerTrust(PGPPublicKey, int) owner-trust} attribute.
 * <li>{@linkplain #updateTrustDb() Recalculate the web-of-trust}.
 * </ul>
 */
public interface TrustDb extends AutoCloseable
{
    /**
     * Utility class for creating an instance of a {@code TrustDb} implementation.
     */
    public static class Helper {
        /**
         * Creates a new instance of a {@code TrustDb} implementation.
         * <p>
         * <b>Important:</b> You must {@linkplain TrustDb#close() close} this instance!
         * <p>
         * There is currently only one single implementation available ({@code TrustDbImpl}),
         * but this might change in the future. Hence, this method should be used instead of
         * directly invoking a constructor!
         * @param file
         *            the trust-database-file ({@code trustdb.gpg}). Must not be <code>null</code>.
         * @param pgpKeyRegistry
         *            the key-registry. Must not be <code>null</code>.
         * @return a new instance of a {@code TrustDb}. Never <code>null</code>.
         */
        public static TrustDb createInstance(final File file, final PgpKeyRegistry pgpKeyRegistry) {
            assertNotNull("file", file);
            assertNotNull("pgpKeyRegistry", pgpKeyRegistry);
            return new TrustDbImpl(file, pgpKeyRegistry);
        }
    }

    @Override
    void close();

    /**
     * Gets the assigned owner-trust value for the given public key.
     * <p>
     * This value specifies how much the user trusts the owner of the given key in his function as notary certifying
     * other keys.
     *
     * @param pgpKey
     *            the key whose owner-trust should be looked up. Must not be <code>null</code>.
     * @return the owner-trust. May be <code>null</code>, if none has been assigned, before.
     * @see #setOwnerTrust(PgpKey, OwnerTrust)
     * @see #getOwnerTrust(PGPPublicKey)
     */
    OwnerTrust getOwnerTrust(PgpKey pgpKey);

    /**
     * Sets the given key's owner-trust.
     * <p>
     * This value specifies how much the user trusts the owner of the given key in his function as notary certifying
     * other keys.
     * <p>
     * The user should mark all own keys with {@link TrustConst#TRUST_ULTIMATE TRUST_ULTIMATE}.
     *
     * @param pgpKey
     *            the key whose owner-trust is to be set. Must not be <code>null</code>.
     * @param ownerTrust
     *            the owner-trust to be assigned. Must not be <code>null</code>.
     * @see #getOwnerTrust(PgpKey)
     * @see #setOwnerTrust(PGPPublicKey, OwnerTrust)
     */
    void setOwnerTrust(PgpKey pgpKey, OwnerTrust ownerTrust);

    /**
     * Gets the assigned owner-trust value for the given public key.
     * <p>
     * This value specifies how much the user trusts the owner of the given key in his function as notary certifying
     * other keys.
     * <p>
     * The given key should be a master key.
     *
     * @param publicKey
     *            the key whose owner-trust should be looked up. Must not be <code>null</code>.
     * @return the owner-trust. May be <code>null</code>, if none has been assigned, before.
     * @see #setOwnerTrust(PGPPublicKey, OwnerTrust)
     * @see #getOwnerTrust(PgpKey)
     */
    OwnerTrust getOwnerTrust(PGPPublicKey publicKey);

    /**
     * Sets the given key's owner-trust.
     * <p>
     * This value specifies how much the user trusts the owner of the given key in his function as notary certifying
     * other keys.
     * <p>
     * The user should mark all own keys with {@link TrustConst#TRUST_ULTIMATE TRUST_ULTIMATE}.
     * <p>
     * The given key should be a master key.
     *
     * @param publicKey
     *            the key whose owner-trust is to be set. Must not be <code>null</code>.
     * @param ownerTrust
     *            the owner-trust to be assigned. Must not be <code>null</code>.
     * @see #getOwnerTrust(PGPPublicKey)
     * @see #setOwnerTrust(PgpKey, OwnerTrust)
     */
    void setOwnerTrust(PGPPublicKey publicKey, OwnerTrust ownerTrust);

    /**
     * Gets the validity of the given key.
     * <p>
     * The validity of a key is the highest validity of all its user-identities (and -attributes). It can be one of
     * {@link Validity}'s numeric values (see also the {@link TrustConst} constants) and it additionally contains the
     * following bit flags:
     * <ul>
     * <li>{@link TrustConst#TRUST_FLAG_DISABLED} - corresponds to {@link #isDisabled(PGPPublicKey)}.
     * <li>{@link TrustConst#TRUST_FLAG_REVOKED} - corresponds to {@link PGPPublicKey#hasRevocation()}.
     * <li>{@link TrustConst#TRUST_FLAG_PENDING_CHECK} - corresponds to {@link #isTrustDbStale()}.
     * </ul>
     * <p>
     * This method does not calculate the validity! It does solely look it up in the trust-database. The validity is
     * (re)calculated by {@link #updateTrustDb()}.
     *
     * @param publicKey
     *            the key whose validity is to be returned. Must not be <code>null</code>.
     * @return the validity with bit flags.
     * @see #getValidityRaw(PGPPublicKey, PgpUserIdNameHash)
     * @deprecated This method exists for compatibility with GnuPG and for easier comparisons between GnuPG's
     *             calculations and the calculations of this code. Do not use it in your code! Use
     *             {@link #getValidity(PGPPublicKey)} instead.
     */
    @Deprecated
    int getValidityRaw(PGPPublicKey publicKey);

    /**
     * Gets the validity of the given user-identity.
     * <ul>
     * <li>{@link TrustConst#TRUST_FLAG_DISABLED} - corresponds to {@link #isDisabled(PGPPublicKey)}.
     * <li>{@link TrustConst#TRUST_FLAG_REVOKED} - corresponds to {@link PGPPublicKey#hasRevocation()}.
     * <li>{@link TrustConst#TRUST_FLAG_PENDING_CHECK} - corresponds to {@link #isTrustDbStale()}.
     * </ul>
     * <p>
     * This method does not calculate the validity! It does solely look it up in the trust-database. The validity is
     * (re)calculated by {@link #updateTrustDb()}.
     *
     * @param publicKey
     *            the key whose validity is to be returned. Must not be <code>null</code>.
     * @param pgpUserIdNameHash
     *            user-id's (or user-attribute's) name-hash. Must not be <code>null</code>.
     * @return the validity with bit flags.
     * @see #getValidityRaw(PGPPublicKey)
     * @deprecated This method exists for compatibility with GnuPG and for easier comparisons between GnuPG's
     *             calculations and the calculations of this code. Do not use it in your code! Use
     *             {@link #getValidity(PGPPublicKey, PgpUserIdNameHash)} instead.
     */
    @Deprecated
    int getValidityRaw(PGPPublicKey publicKey, PgpUserIdNameHash pgpUserIdNameHash);

    /**
     * Gets the validity of the given key.
     * <p>
     * The validity of a key is the highest validity of all its user-identities (and -attributes).
     * <p>
     * This method does not calculate the validity! It does solely look it up in the trust-database. The validity is
     * (re)calculated by {@link #updateTrustDb()}.
     *
     * @param pgpKey
     *            the key whose validity to look up. Must not be <code>null</code>.
     * @return the validity of the given {@code publicKey}. Never <code>null</code>.
     * @see #getValidity(PgpKey, PgpUserIdNameHash)
     * @see #getValidity(PGPPublicKey)
     */
    Validity getValidity(PgpKey pgpKey);

    /**
     * Gets the validity of the given user-identity (or -attribute).
     * <p>
     * This method does not calculate the validity! It does solely look it up in the trust-database. The validity is
     * (re)calculated by {@link #updateTrustDb()}.
     *
     * @param pgpUserId
     *            the user-identity (or -attribute) whose validity to look up. Must not be <code>null</code>.
     * @return the validity of the given user-identity. Never <code>null</code>.
     * @see #getValidity(PgpKey)
     * @see #getValidity(PGPPublicKey, PgpUserIdNameHash)
     */
    Validity getValidity(PgpUserId pgpUserId);

    /**
     * Gets the validity of the given key.
     * <p>
     * The validity of a key is the highest validity of all its user-identities (and -attributes).
     * <p>
     * This method does not calculate the validity! It does solely look it up in the trust-database. The validity is
     * (re)calculated by {@link #updateTrustDb()}.
     *
     * @param publicKey
     *            the key whose validity to look up. Must not be <code>null</code>.
     * @return the validity of the given {@code publicKey}. Never <code>null</code>.
     * @see #getValidity(PGPPublicKey, PgpUserIdNameHash)
     */
    Validity getValidity(PGPPublicKey publicKey);

    /**
     * Gets the validity of the given user-identity (or -attribute).
     * <p>
     * This method does not calculate the validity! It does solely look it up in the trust-database. The validity is
     * (re)calculated by {@link #updateTrustDb()}.
     *
     * @param publicKey
     *            the key whose validity to look up. Must not be <code>null</code>.
     * @param pgpUserIdNameHash
     *            the name-hash of the user-identity (or -attribute) whose validity to look up. Must not be
     *            <code>null</code>.
     * @return the validity of the given user-identity. Never <code>null</code>.
     * @see #getValidity(PGPPublicKey)
     */
    Validity getValidity(PGPPublicKey publicKey, PgpUserIdNameHash pgpUserIdNameHash);

    /**
     * Marks all those keys that we have a secret key for as ultimately trusted. If we have a secret/private key, we
     * assume it to be *our* key and we always trust ourselves.
     *
     * @param onlyIfMissing
     *            whether only those keys' owner-trust should be set which do not yet have an owner-trust assigned.
     */
    void updateUltimatelyTrustedKeysFromAvailableSecretKeys(boolean onlyIfMissing);

    boolean isExpired(PGPPublicKey publicKey);

    /**
     * Determines whether the specified key is marked as disabled.
     *
     * @param pgpKey
     *            the key whose status to query. Must not be <code>null</code>.
     * @return <code>true</code>, if the key is marked as disabled; <code>false</code>, if the key is enabled.
     */
    boolean isDisabled(PgpKey pgpKey);

    /**
     * Enables or disabled the specified key.
     *
     * @param pgpKey
     *            the key whose status to query. Must not be <code>null</code>.
     * @param disabled
     *            <code>true</code> to disable the key; <code>false</code> to enable it.
     */
    void setDisabled(PgpKey pgpKey, boolean disabled);

    /**
     * Determines whether the specified key is marked as disabled.
     * <p>
     * The key should be a master-key.
     *
     * @param publicKey
     *            the key whose status to query. Must not be <code>null</code>. This should be a master-key.
     * @return <code>true</code>, if the key is marked as disabled; <code>false</code>, if the key is enabled.
     */
    boolean isDisabled(PGPPublicKey publicKey);

    /**
     * Enables or disabled the specified key.
     * <p>
     * The key should be a master-key.
     *
     * @param publicKey
     *            the key whose status to query. Must not be <code>null</code>. This should be a master-key.
     * @param disabled
     *            <code>true</code> to disable the key; <code>false</code> to enable it.
     */
    void setDisabled(PGPPublicKey publicKey, boolean disabled);

    /**
     * Determines if the trust-database is stale. It becomes stale, if it is either explicitly
     * {@linkplain #markTrustDbStale() marked stale} or if a key expires.
     * <p>
     * <b>Important:</b> It does not become stale when a key ring file is modified! Thus, when adding new keys,
     * {@link #markTrustDbStale()} or {@link #updateTrustDb()} must be invoked.
     *
     * @return <code>true</code>, if the trust-database is stale; <code>false</code>, if it is up-to-date.
     * @see #markTrustDbStale()
     * @see #updateTrustDb()
     * @see #updateTrustDbIfNeeded()
     */
    boolean isTrustDbStale();

    /**
     * Marks the trust-db as being stale.
     * <p>
     * Either this method or {@link #updateTrustDb()} must be invoked whenever a new key was added to the key ring,
     * because the WOT-related code does not keep track of key-ring-changes ({@link #isTrustDbStale()} does not detect
     * them).
     *
     * @see #isTrustDbStale()
     * @see #updateTrustDb()
     */
    void markTrustDbStale();

    /**
     * Update the {@code trustdb.gpg} by recalculating all keys' validities, if it is needed. An update is needed, if
     * the {@linkplain #isTrustDbStale() trust-db is stale}.
     *
     * @see #updateTrustDb()
     * @see #isTrustDbStale()
     */
    void updateTrustDbIfNeeded();

    /**
     * Update the {@code trustdb.gpg} by recalculating all keys' validities.
     * <p>
     * Either this method or {@link #markTrustDbStale()} must be invoked whenever a new key was added to the key ring,
     * because the WOT-related code does not keep track of key-ring-changes ({@link #isTrustDbStale()} does not detect
     * them).
     *
     * @see #updateTrustDbIfNeeded()
     */
    void updateTrustDb();

}