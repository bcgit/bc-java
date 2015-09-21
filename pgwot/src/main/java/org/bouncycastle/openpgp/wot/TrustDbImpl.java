package org.bouncycastle.openpgp.wot;

import static org.bouncycastle.openpgp.wot.internal.Util.*;

import java.io.File;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.wot.internal.PgpKeyTrust;
import org.bouncycastle.openpgp.wot.internal.PgpUserIdTrust;
import org.bouncycastle.openpgp.wot.internal.TrustDbIo;
import org.bouncycastle.openpgp.wot.internal.TrustRecord;
import org.bouncycastle.openpgp.wot.internal.TrustRecordType;
import org.bouncycastle.openpgp.wot.key.PgpKey;
import org.bouncycastle.openpgp.wot.key.PgpKeyFingerprint;
import org.bouncycastle.openpgp.wot.key.PgpKeyId;
import org.bouncycastle.openpgp.wot.key.PgpKeyRegistry;
import org.bouncycastle.openpgp.wot.key.PgpUserId;
import org.bouncycastle.openpgp.wot.key.PgpUserIdNameHash;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * API implementation for working with <a href="https://gnupg.org/">GnuPG</a>'s {@code trustdb.gpg}.
 * <p>
 * This class was mostly ported from the GnuPG's {@code trustdb.h} and {@code trustdb.c} files.
 *
 * @author Marco หงุ่ยตระกูล-Schulze - marco at codewizards dot co
 */
public class TrustDbImpl implements AutoCloseable, TrustConst, TrustDb
{
    private static final Logger logger = LoggerFactory.getLogger(TrustDbImpl.class);

    private final TrustDbIo trustDbIo;
    private final PgpKeyRegistry pgpKeyRegistry;

    private long startTime;
    private long nextExpire;
    private Map<PgpKeyFingerprint, PgpKeyTrust> fingerprint2PgpKeyTrust;
    private Set<PgpKeyFingerprint> klist;
    private Set<PgpKeyFingerprint> fullTrust;
    private DateFormat dateFormatIso8601WithTime;

    /**
     * Create a {@code TrustDbImpl} instance with the given {@code trustdb.gpg} file and the given key-registry.
     * <p>
     * <b>Important:</b> You must {@linkplain #close() close} this instance!
     *
     * @param file
     *            the trust-database-file ({@code trustdb.gpg}). Must not be <code>null</code>.
     * @param pgpKeyRegistry
     *            the key-registry. Must not be <code>null</code>.
     */
    public TrustDbImpl(final File file, final PgpKeyRegistry pgpKeyRegistry)
    {
        assertNotNull("file", file);
        this.pgpKeyRegistry = assertNotNull("pgpKeyRegistry", pgpKeyRegistry);
        this.trustDbIo = new TrustDbIo(file);
    }

    @Override
    public void close()
    {
        trustDbIo.close();
    }

    public DateFormat getDateFormatIso8601WithTime()
    {
        if (dateFormatIso8601WithTime == null)
            dateFormatIso8601WithTime = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");

        return dateFormatIso8601WithTime;
    }

    protected PgpKeyTrust getPgpKeyTrust(final PgpKey pgpKey)
    {
        PgpKeyTrust pgpKeyTrust = fingerprint2PgpKeyTrust.get(pgpKey.getPgpKeyFingerprint());
        if (pgpKeyTrust == null)
        {
            pgpKeyTrust = new PgpKeyTrust(pgpKey);
            fingerprint2PgpKeyTrust.put(pgpKeyTrust.getPgpKeyFingerprint(), pgpKeyTrust);
        }
        return pgpKeyTrust;
    }

    // reset_trust_records(void)
    protected void resetTrustRecords()
    {
        TrustRecord record;
        long recordNum = 0;
        int count = 0, nreset = 0;

        while ((record = trustDbIo.getTrustRecord(++recordNum)) != null)
        {
            if (record.getType() == TrustRecordType.TRUST)
            {
                final TrustRecord.Trust trust = (TrustRecord.Trust) record;
                ++count;
                if (trust.getMinOwnerTrust() != 0)
                {
                    trust.setMinOwnerTrust((short) 0);
                    trustDbIo.putTrustRecord(record);
                }
            }
            else if (record.getType() == TrustRecordType.VALID)
            {
                final TrustRecord.Valid valid = (TrustRecord.Valid) record;
                if (((valid.getValidity() & TRUST_MASK) != 0)
                        || valid.getMarginalCount() != 0
                        || valid.getFullCount() != 0)
                {

                    valid.setValidity((short) (valid.getValidity() & (~TRUST_MASK)));
                    valid.setMarginalCount((short) 0);
                    valid.setFullCount((short) 0);
                    nreset++;
                    trustDbIo.putTrustRecord(record);
                }
            }
        }

        logger.debug("resetTrustRecords: {} keys processed ({} validity counts cleared)", count, nreset);
    }

    @Override
    public OwnerTrust getOwnerTrust(PgpKey pgpKey)
    {
        assertNotNull("pgpKey", pgpKey);
        if (pgpKey.getMasterKey() != null)
            pgpKey = pgpKey.getMasterKey();

        return getOwnerTrust(pgpKey.getPublicKey());
    }

    @Override
    public void setOwnerTrust(PgpKey pgpKey, final OwnerTrust ownerTrust)
    {
        assertNotNull("pgpKey", pgpKey);
        assertNotNull("ownerTrust", ownerTrust);
        if (pgpKey.getMasterKey() != null)
            pgpKey = pgpKey.getMasterKey();

        setOwnerTrust(pgpKey.getPublicKey(), ownerTrust);
    }

    @Override
    public OwnerTrust getOwnerTrust(final PGPPublicKey publicKey)
    {
        assertNotNull("publicKey", publicKey);
        // if (trustdb_args.no_trustdb && opt.trust_model == TM_ALWAYS)
        // return TRUST_UNKNOWN; // TODO maybe we should support other trust models...

        TrustRecord.Trust trust = getTrustByPublicKey(publicKey);
        if (trust == null)
            return OwnerTrust.UNKNOWN;

        return OwnerTrust.fromNumericValue(trust.getOwnerTrust() & TRUST_MASK);
    }

    @Override
    public void setOwnerTrust(final PGPPublicKey publicKey, final OwnerTrust ownerTrust)
    {
        assertNotNull("publicKey", publicKey);
        assertNotNull("ownerTrust", ownerTrust);

        TrustRecord.Trust trust = getTrustByPublicKey(publicKey);
        if (trust == null)
        {
            // No record yet - create a new one.
            trust = new TrustRecord.Trust();
            trust.setFingerprint(publicKey.getFingerprint());
        }

        int ownerTrustAdditionalFlags = trust.getOwnerTrust() & ~TRUST_MASK;

        trust.setOwnerTrust((short) (ownerTrust.getNumericValue() | ownerTrustAdditionalFlags));
        trustDbIo.putTrustRecord(trust);

        markTrustDbStale();
        trustDbIo.flush();
    }

    protected TrustRecord.Trust getTrustByPublicKey(PGPPublicKey publicKey)
    {
        assertNotNull("publicKey", publicKey);
        TrustRecord.Trust trust = trustDbIo.getTrustByPublicKey(publicKey);
        return trust;
    }

    @Override
    @Deprecated
    public synchronized int getValidityRaw(final PGPPublicKey publicKey)
    {
        assertNotNull("publicKey", publicKey);
        return _getValidity(publicKey, (PgpUserIdNameHash) null, true);
    }

    @Override
    @Deprecated
    public synchronized int getValidityRaw(final PGPPublicKey publicKey, final PgpUserIdNameHash pgpUserIdNameHash)
    {
        assertNotNull("publicKey", publicKey);
        assertNotNull("pgpUserIdNameHash", pgpUserIdNameHash);
        return _getValidity(publicKey, pgpUserIdNameHash, true);
    }

    @Override
    public Validity getValidity(final PgpKey pgpKey)
    {
        assertNotNull("pgpKey", pgpKey);
        return getValidity(pgpKey.getPublicKey());
    }

    @Override
    public Validity getValidity(final PgpUserId pgpUserId)
    {
        assertNotNull("pgpUserId", pgpUserId);
        return getValidity(pgpUserId.getPgpKey().getPublicKey(), pgpUserId.getNameHash());
    }

    @Override
    public Validity getValidity(final PGPPublicKey publicKey)
    {
        assertNotNull("publicKey", publicKey);
        final int numericValue = _getValidity(publicKey, (PgpUserIdNameHash) null, false);
        return Validity.fromNumericValue(numericValue);
    }

    @Override
    public Validity getValidity(final PGPPublicKey publicKey, final PgpUserIdNameHash pgpUserIdNameHash)
    {
        assertNotNull("publicKey", publicKey);
        assertNotNull("pgpUserIdNameHash", pgpUserIdNameHash);
        final int numericValue = _getValidity(publicKey, pgpUserIdNameHash, false);
        return Validity.fromNumericValue(numericValue);
    }

    /**
     * Ported from
     * {@code unsigned int tdb_get_validity_core (PKT_public_key *pk, PKT_user_id *uid, PKT_public_key *main_pk)}
     */
    protected synchronized int _getValidity(final PGPPublicKey publicKey, final PgpUserIdNameHash pgpUserIdNameHash,
            final boolean withFlags)
    {
        assertNotNull("publicKey", publicKey);
        TrustRecord.Trust trust = getTrustByPublicKey(publicKey);
        if (trust == null)
            return TRUST_UNKNOWN;

        // Loop over all user IDs
        long recordNum = trust.getValidList();
        int validity = 0;
        int flags = 0;
        // Currently, neither this class nor GnuPG stores any flags in the valid-records, but we're robust
        // and thus expect validateKey(...) to maybe put flags into the validity DB, later. Therefore,
        // we track them here separately (additive for all sub-keys if no user-id-name-hash is given).
        while (recordNum != 0)
        {
            TrustRecord.Valid valid = trustDbIo.getTrustRecord(recordNum, TrustRecord.Valid.class);
            assertNotNull("valid", valid);

            if (pgpUserIdNameHash != null)
            {
                // If a user ID is given we return the validity for that
                // user ID ONLY. If the namehash is not found, then there
                // is no validity at all (i.e. the user ID wasn't signed).
                if (pgpUserIdNameHash.equals(valid.getNameHash()))
                {
                    validity = valid.getValidity() & TRUST_MASK;
                    flags = valid.getValidity() & ~TRUST_MASK;
                    break;
                }
            }
            else
            {
                // If no user ID is given, we take the maximum validity over all user IDs
                validity = Math.max(validity, valid.getValidity() & TRUST_MASK);
                flags |= valid.getValidity() & ~TRUST_MASK;
            }
            recordNum = valid.getNext();
        }

        if (withFlags)
        {
            validity |= flags;

            if ((trust.getOwnerTrust() & TRUST_FLAG_DISABLED) != 0)
                validity |= TRUST_FLAG_DISABLED;

            if (publicKey.hasRevocation())
                validity |= TRUST_FLAG_REVOKED;

            if (isTrustDbStale())
                validity |= TRUST_FLAG_PENDING_CHECK;
        }
        return validity;
    }

    // static void update_validity (PKT_public_key *pk, PKT_user_id *uid, int depth, int validity)
    protected void updateValidity(PgpUserId pgpUserId, int depth, int validity, int fullCount, int marginalCount)
    {
        assertNotNull("pgpUserId", pgpUserId);
        assertNonNegativeShort("depth", depth);
        assertNonNegativeShort("validity", validity);
        assertNonNegativeShort("fullCount", fullCount);
        assertNonNegativeShort("marginalCount", marginalCount);

        TrustRecord.Trust trust = getTrustByPublicKey(pgpUserId.getPgpKey().getPublicKey());
        if (trust == null)
        {
            // No record yet - create a new one.
            trust = new TrustRecord.Trust();
            trust.setFingerprint(pgpUserId.getPgpKey().getPgpKeyFingerprint().getBytes());
            trustDbIo.putTrustRecord(trust);
        }

        TrustRecord.Valid valid = null;

        // locate an existing Valid record
        final byte[] pgpUserIdNameHashBytes = pgpUserId.getNameHash().getBytes();
        long recordNum = trust.getValidList();
        while (recordNum != 0)
        {
            valid = trustDbIo.getTrustRecord(recordNum, TrustRecord.Valid.class);
            if (Arrays.equals(valid.getNameHash(), pgpUserIdNameHashBytes))
                break;

            recordNum = valid.getNext();
        }

        if (recordNum == 0)
        { // insert a new validity record
            valid = new TrustRecord.Valid();
            valid.setNameHash(pgpUserIdNameHashBytes);
            valid.setNext(trust.getValidList());
            trustDbIo.putTrustRecord(valid); // assigns the recordNum of the new record
            trust.setValidList(valid.getRecordNum());
        }

        valid.setValidity((short) validity);
        valid.setFullCount((short) fullCount);
        valid.setMarginalCount((short) marginalCount);
        trust.setDepth((short) depth);
        trustDbIo.putTrustRecord(trust);
        trustDbIo.putTrustRecord(valid);
    }

    private static void assertNonNegativeShort(final String name, final int value)
    {
        assertNotNull("name", name);

        if (value < 0)
            throw new IllegalArgumentException(name + " < 0");

        if (value > Short.MAX_VALUE)
            throw new IllegalArgumentException(name + " > Short.MAX_VALUE");
    }

    /* (non-Javadoc)
     * @see org.bouncycastle.openpgp.wot.TrustDb#updateUltimatelyTrustedKeysFromAvailableSecretKeys(boolean)
     */
    @Override
    public void updateUltimatelyTrustedKeysFromAvailableSecretKeys(boolean onlyIfMissing)
    {
        for (final PgpKey masterKey : pgpKeyRegistry.getMasterKeys())
        {
            if (masterKey.getSecretKey() == null)
                continue;

            TrustRecord.Trust trust = trustDbIo.getTrustByPublicKey(masterKey.getPublicKey());
            if (trust == null
                    || trust.getOwnerTrust() == TRUST_UNKNOWN
                    || !onlyIfMissing)
            {

                if (trust == null)
                {
                    trust = new TrustRecord.Trust();
                    trust.setFingerprint(masterKey.getPgpKeyFingerprint().getBytes());
                }

                trust.setDepth((short) 0);
                trust.setOwnerTrust((short) TRUST_ULTIMATE);
                trustDbIo.putTrustRecord(trust);
            }
        }
    }

    protected Set<PgpKeyFingerprint> getUltimatelyTrustedKeyFingerprints()
    {
        Set<PgpKeyFingerprint> result = new HashSet<PgpKeyFingerprint>();
        TrustRecord record;
        long recordNum = 0;
        while ((record = trustDbIo.getTrustRecord(++recordNum)) != null)
        {
            if (record.getType() == TrustRecordType.TRUST)
            {
                TrustRecord.Trust trust = (TrustRecord.Trust) record;
                if ((trust.getOwnerTrust() & TRUST_MASK) == TRUST_ULTIMATE)
                    result.add(new PgpKeyFingerprint(trust.getFingerprint()));
            }
        }
        return result;
    }

    @Override
    public boolean isExpired(PGPPublicKey publicKey)
    {
        assertNotNull("publicKey", publicKey);

        final Date creationTime = publicKey.getCreationTime();

        final long validSeconds = publicKey.getValidSeconds();
        if (validSeconds != 0)
        {
            long validUntilTimestamp = creationTime.getTime() + (validSeconds * 1000);
            return validUntilTimestamp < System.currentTimeMillis();
        }
        return false;
        // TODO there seem to be keys (very old keys) that seem to encode the validity differently.
        // For example, the real key 86A331B667F0D02F is expired according to my gpg, but it
        // is not expired according to this code :-( I experimented with checking the userIds, but to no avail.
        // It's a very small number of keys only, hence I ignore it for now ;-)
    }

    @Override
    public boolean isDisabled(PgpKey pgpKey)
    {
        assertNotNull("pgpKey", pgpKey);
        if (pgpKey.getMasterKey() != null)
            pgpKey = pgpKey.getMasterKey();

        return isDisabled(pgpKey.getPublicKey());
    }

    @Override
    public void setDisabled(PgpKey pgpKey, final boolean disabled)
    {
        assertNotNull("pgpKey", pgpKey);
        if (pgpKey.getMasterKey() != null)
            pgpKey = pgpKey.getMasterKey();

        setDisabled(pgpKey.getPublicKey(), disabled);
    }

    @Override
    public boolean isDisabled(final PGPPublicKey publicKey)
    {
        assertNotNull("publicKey", publicKey);
        TrustRecord.Trust trust = trustDbIo.getTrustByFingerprint(publicKey.getFingerprint());
        if (trust == null)
            return false;

        return (trust.getOwnerTrust() & TRUST_FLAG_DISABLED) != 0;
    }

    @Override
    public void setDisabled(final PGPPublicKey publicKey, final boolean disabled)
    {
        assertNotNull("publicKey", publicKey);
        TrustRecord.Trust trust = trustDbIo.getTrustByFingerprint(publicKey.getFingerprint());
        if (trust == null)
        {
            trust = new TrustRecord.Trust();
            trust.setFingerprint(publicKey.getFingerprint());
        }

        int ownerTrust = trust.getOwnerTrust();
        if (disabled)
            ownerTrust = ownerTrust | TRUST_FLAG_DISABLED;
        else
            ownerTrust = ownerTrust & ~TRUST_FLAG_DISABLED;

        trust.setOwnerTrust((short) ownerTrust);

        trustDbIo.putTrustRecord(trust);
        trustDbIo.flush();
    }

    @Override
    public synchronized boolean isTrustDbStale()
    {
        final Config config = Config.getInstance();
        final TrustRecord.Version version = trustDbIo.getTrustRecord(0, TrustRecord.Version.class);
        assertNotNull("version", version);

        if (config.getTrustModel() != version.getTrustModel())
        {
            TrustModel configTrustModel;
            try
            {
                configTrustModel = TrustModel.fromNumericId(config.getTrustModel());
            } catch (IllegalArgumentException x)
            {
                configTrustModel = null;
            }

            TrustModel versionTrustModel;
            try
            {
                versionTrustModel = TrustModel.fromNumericId(version.getTrustModel());
            } catch (IllegalArgumentException x)
            {
                versionTrustModel = null;
            }

            logger.debug("isTrustDbStale: stale=true config.trustModel={} ({}) trustDb.trustModel={} ({})",
                    config.getTrustModel(), configTrustModel, version.getTrustModel(), versionTrustModel);

            return true;
        }

        if (config.getCompletesNeeded() != version.getCompletesNeeded())
        {
            logger.debug("isTrustDbStale: stale=true config.completesNeeded={} trustDb.completesNeeded={}",
                    config.getCompletesNeeded(), version.getCompletesNeeded());

            return true;
        }

        if (config.getMarginalsNeeded() != version.getMarginalsNeeded())
        {
            logger.debug("isTrustDbStale: stale=true config.marginalsNeeded={} trustDb.marginalsNeeded={}",
                    config.getMarginalsNeeded(), version.getMarginalsNeeded());

            return true;
        }

        if (config.getMaxCertDepth() != version.getCertDepth())
        {
            logger.debug("isTrustDbStale: stale=true config.maxCertDepth={} trustDb.maxCertDepth={}",
                    config.getMaxCertDepth(), version.getCertDepth());

            return true;
        }

        final Date now = new Date();
        if (version.getNextCheck().before(now))
        {
            logger.debug("isTrustDbStale: stale=true nextCheck={} now={}",
                    getDateFormatIso8601WithTime().format(version.getNextCheck()),
                    getDateFormatIso8601WithTime().format(now));

            return true;
        }

        logger.trace("isTrustDbStale: stale=false");
        return false;
    }

    @Override
    public synchronized void markTrustDbStale()
    {
        final TrustRecord.Version version = trustDbIo.getTrustRecord(0, TrustRecord.Version.class);
        assertNotNull("version", version);
        version.setNextCheck(new Date(0));
        trustDbIo.putTrustRecord(version);
    }

    @Override
    public synchronized void updateTrustDbIfNeeded()
    {
        if (isTrustDbStale())
            updateTrustDb();
    }

    /**
     * {@inheritDoc}
     * <p>
     * Inspired by {@code static int validate_keys (int interactive)}. This function was not ported, because the
     * implementation looked overly complicated. This method here is a re-implementation from scratch. It still seems to
     * come very closely to the behaviour of GnuPG's original code.
     */
    @Override
    public synchronized void updateTrustDb()
    {
        final Config config = Config.getInstance();
        try
        {
            fingerprint2PgpKeyTrust = new HashMap<>();
            fullTrust = new HashSet<>();

            startTime = System.currentTimeMillis() / 1000;
            nextExpire = Long.MAX_VALUE;

            resetTrustRecords();

            final Set<PgpKeyFingerprint> ultimatelyTrustedKeyFingerprints = getUltimatelyTrustedKeyFingerprints();
            if (ultimatelyTrustedKeyFingerprints.isEmpty())
            {
                logger.warn("updateTrustDb: There are no ultimately trusted keys!");
                return;
            }

            // mark all UTKs as used and fully_trusted and set validity to ultimate
            for (final PgpKeyFingerprint utkFpr : ultimatelyTrustedKeyFingerprints)
            {
                final PgpKey utk = pgpKeyRegistry.getPgpKey(utkFpr);
                if (utk == null)
                {
                    logger.warn("public key of ultimately trusted key '{}' not found!", utkFpr.toHumanString());
                    continue;
                }

                fullTrust.add(utkFpr);

                for (PgpUserId pgpUserId : utk.getPgpUserIds())
                    updateValidity(pgpUserId, 0, TRUST_ULTIMATE, 0, 0);

                final long expireDate = getExpireTimestamp(utk.getPublicKey());
                if (expireDate >= startTime && expireDate < nextExpire)
                    nextExpire = expireDate;
            }

            klist = ultimatelyTrustedKeyFingerprints;

            for (int depth = 0; depth < config.getMaxCertDepth(); ++depth)
            {
                final List<PgpKey> validatedKeys = validateKeyList();

                klist = new HashSet<>();
                for (PgpKey pgpKey : validatedKeys)
                {
                    PgpKeyTrust pgpKeyTrust = getPgpKeyTrust(pgpKey);
                    klist.add(pgpKey.getPgpKeyFingerprint());

                    for (final PgpUserIdTrust pgpUserIdTrust : pgpKeyTrust.getPgpUserIdTrusts())
                    {
                        final PgpUserId pgpUserId = pgpUserIdTrust.getPgpUserId();

                        final int validity = pgpUserIdTrust.getValidity();
                        updateValidity(pgpUserId, depth, validity,
                                pgpUserIdTrust.getFullCount(), pgpUserIdTrust.getMarginalCount());

                        if (validity >= TRUST_FULL)
                            fullTrust.add(pgpUserIdTrust.getPgpUserId().getPgpKey().getPgpKeyFingerprint());
                    }

                    final long expireDate = getExpireTimestamp(pgpKey.getPublicKey());
                    if (expireDate >= startTime && expireDate < nextExpire)
                        nextExpire = expireDate;
                }

                logger.debug("updateTrustDb: depth={} keys={}",
                        depth, validatedKeys.size());
            }

            final Date nextExpireDate = new Date(nextExpire * 1000);
            trustDbIo.updateVersionRecord(nextExpireDate);

            trustDbIo.flush();

            logger.info("updateTrustDb: Next trust-db expiration date: {}",
                    getDateFormatIso8601WithTime().format(nextExpireDate));
        } finally
        {
            fingerprint2PgpKeyTrust = null;
            klist = null;
            fullTrust = null;
        }
    }

    private long getExpireTimestamp(PGPPublicKey pk)
    {
        final long validSeconds = pk.getValidSeconds();
        if (validSeconds == 0)
            return Long.MAX_VALUE;

        final long result = (pk.getCreationTime().getTime() / 1000) + validSeconds;
        return result;
    }

    /**
     * Inspired by {@code static struct key_array *validate_key_list (KEYDB_HANDLE hd, KeyHashTable full_trust,
     * struct key_item *klist, u32 curtime, u32 *next_expire)}, but re-implemented from scratch - see
     * {@link #updateTrustDb()}.
     *
     * @return the keys that were processed by this method.
     */
    private List<PgpKey> validateKeyList()
    {
        final List<PgpKey> result = new ArrayList<>();
        final Set<PgpKeyFingerprint> signedPgpKeyFingerprints = new HashSet<>();
        for (PgpKeyFingerprint signingPgpKeyFingerprint : klist)
            signedPgpKeyFingerprints.addAll(pgpKeyRegistry.getPgpKeyFingerprintsSignedBy(signingPgpKeyFingerprint));

        signedPgpKeyFingerprints.removeAll(fullTrust); // no need to validate those that are already fully trusted

        for (final PgpKeyFingerprint pgpKeyFingerprint : signedPgpKeyFingerprints)
        {
            final PgpKey pgpKey = pgpKeyRegistry.getPgpKey(pgpKeyFingerprint);
            if (pgpKey == null)
            {
                logger.warn("key disappeared: fingerprint='{}'", pgpKeyFingerprint);
                continue;
            }
            result.add(pgpKey);
            validateKey(pgpKey);
        }
        return result;
    }

    /**
     * Inspired by {@code static int validate_one_keyblock (KBNODE kb, struct key_item *klist,
     * u32 curtime, u32 *next_expire)}, but re-implemented from scratch - see {@link #updateTrustDb()}.
     *
     * @param pgpKey
     *            the pgp-key to be validated. Must not be <code>null</code>.
     */
    private void validateKey(final PgpKey pgpKey)
    {
        assertNotNull("pgpKey", pgpKey);
        logger.debug("validateKey: {}", pgpKey);

        final Config config = Config.getInstance();
        final PgpKeyTrust pgpKeyTrust = getPgpKeyTrust(pgpKey);

        final boolean expired = isExpired(pgpKey.getPublicKey());
        // final boolean disabled = isDisabled(pgpKey.getPublicKey());
        final boolean revoked = pgpKey.getPublicKey().hasRevocation();

        for (final PgpUserId pgpUserId : pgpKey.getPgpUserIds())
        {
            final PgpUserIdTrust pgpUserIdTrust = pgpKeyTrust.getPgpUserIdTrust(pgpUserId);

            pgpUserIdTrust.setValidity(0); // TRUST_UNKNOWN = 0
            pgpUserIdTrust.setUltimateCount(0);
            pgpUserIdTrust.setFullCount(0);
            pgpUserIdTrust.setMarginalCount(0);

            if (expired)
                continue;

            // if (disabled)
            // continue;

            if (revoked)
                continue;

            for (PGPSignature certification : pgpKeyRegistry.getSignatures(pgpUserId))
            {
                // It seems, the PGP trust model does not care about the certification level :-(
                // Any of the 3 DEFAULT, CASUAL, POSITIVE is as fine as the other -
                // there is no difference (at least according to my tests).
                if (certification.getSignatureType() != PGPSignature.DEFAULT_CERTIFICATION
                        && certification.getSignatureType() != PGPSignature.CASUAL_CERTIFICATION
                        && certification.getSignatureType() != PGPSignature.POSITIVE_CERTIFICATION)
                    continue;

                final PgpKey signingKey = pgpKeyRegistry.getPgpKey(new PgpKeyId(certification.getKeyID()));
                if (signingKey == null)
                    continue;

                final OwnerTrust signingOwnerTrust = getOwnerTrust(signingKey.getPublicKey());
                if (signingKey.getPgpKeyId().equals(pgpKey.getPgpKeyId())
                        && signingOwnerTrust != OwnerTrust.ULTIMATE)
                {
                    // It's *not* our own key [*not* ULTIMATE] - hence we ignore the self-signature.
                    continue;
                }

                int signingValidity = getValidityRaw(signingKey.getPublicKey()) & TRUST_MASK;
                if (signingValidity <= TRUST_MARGINAL)
                {
                    // If the signingKey is trusted only marginally or less, we ignore the certification completely.
                    // Only fully trusted keys are taken into account for transitive trust.
                    continue;
                }

                // The owner-trust of the signing key is relevant.
                switch (signingOwnerTrust)
                {
                    case ULTIMATE:
                        pgpUserIdTrust.incUltimateCount();
                        break;
                    case FULL:
                        pgpUserIdTrust.incFullCount();
                        break;
                    case MARGINAL:
                        pgpUserIdTrust.incMarginalCount();
                        break;
                    default: // ignoring!
                        break;
                }
            }

            if (pgpUserIdTrust.getUltimateCount() >= 1)
                pgpUserIdTrust.setValidity(TRUST_FULL);
            else if (pgpUserIdTrust.getFullCount() >= config.getCompletesNeeded())
                pgpUserIdTrust.setValidity(TRUST_FULL);
            else if (pgpUserIdTrust.getFullCount() + pgpUserIdTrust.getMarginalCount() >= config.getMarginalsNeeded())
                pgpUserIdTrust.setValidity(TRUST_FULL);
            else if (pgpUserIdTrust.getFullCount() >= 1 || pgpUserIdTrust.getMarginalCount() >= 1)
                pgpUserIdTrust.setValidity(TRUST_MARGINAL);
        }
    }
}
