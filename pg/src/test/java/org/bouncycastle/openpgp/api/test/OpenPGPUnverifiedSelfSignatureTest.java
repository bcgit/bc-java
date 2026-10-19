package org.bouncycastle.openpgp.api.test;

import java.io.IOException;
import java.util.Date;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.PreferredAlgorithms;
import org.bouncycastle.bcpg.sig.RevocationReasonTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.util.Arrays;

/**
 * Regression test: a self-signature which does not verify must play no part in evaluating a certificate.
 * <p>
 * RFC 9580, section 5.2.3.10: "An implementation that encounters multiple self-signatures on the same object
 * MUST select the most recent valid self-signature and ignore all other self-signatures." The certificate
 * selected the most recent <i>effective</i> self-signature and verified it only afterwards, if at all, so an
 * appended signature that does not verify - which anyone can add to a published certificate, no secret key
 * needed - was used before it was found invalid:
 * <ul>
 * <li>a newer one with no Key Expiration Time revived an expired certificate, since the expiration lookup gave
 * up on finding the newest binding invalid and that read as "never expires";</li>
 * <li>a newer one, or a hard revocation of any date, unbound the key, subkey or user ID it was on, since the
 * binding check verified only the chain it had selected and never fell back to an older valid one;</li>
 * <li>a newer user ID certification supplied the recipient's Features and algorithm preferences, which were
 * read without any validity check, downgrading the encryption mode a sender picks.</li>
 * </ul>
 * Each forged signature here is a real self-signature with its signature value corrupted, so it is
 * well-formed, names the genuine issuer, and does not verify. The controls append the same signature
 * uncorrupted, where a newer valid self-signature legitimately takes precedence.
 */
public class OpenPGPUnverifiedSelfSignatureTest
    extends APITest
{
    private static final long MILLIS_PER_DAY = 24 * 60 * 60 * 1000L;
    private static final long MILLIS_PER_HOUR = 60 * 60 * 1000L;
    // OpenPGPKeyGenerator gives a generated key a default expiration of 5 years.
    private static final long BEYOND_DEFAULT_EXPIRY = 6 * 365 * MILLIS_PER_DAY;

    private static final String USER_ID = "Alice <alice@example.com>";

    public String getName()
    {
        return "OpenPGPUnverifiedSelfSignatureTest";
    }

    protected void performTestWith(OpenPGPApi api)
        throws PGPException, IOException
    {
        int[] versions = new int[]{PublicKeyPacket.VERSION_4, PublicKeyPacket.VERSION_6};
        for (int i = 0; i != versions.length; i++)
        {
            int version = versions[i];

            unverifiedUserIdCertificationDoesNotReviveExpiredKey(api, version);
            validUserIdCertificationRevivesExpiredKey(api, version);

            unverifiedDirectKeySignatureDoesNotUnbindKey(api, version);
            unverifiedHardRevocationDoesNotRevokeKey(api, version);
            validHardRevocationRevokesKey(api, version);
            unverifiedSubkeyBindingDoesNotUnbindSubkey(api, version);
            unverifiedUserIdCertificationDoesNotUnbindUserId(api, version);

            unverifiedUserIdCertificationDoesNotChangePreferences(api, version);
            validUserIdCertificationChangesPreferences(api, version);
        }
    }

    private void unverifiedUserIdCertificationDoesNotReviveExpiredKey(OpenPGPApi api, int version)
        throws PGPException, IOException
    {
        Date now = new Date();
        OpenPGPKey key = expiredKey(api, version);
        OpenPGPCertificate cert = reparse(api, key.toCertificate());

        isFalse("test setup: v" + version + " key should be expired", cert.getPrimaryKey().isBoundAt(now));
        isTrue("test setup: v" + version + " key should offer no encryption key", cert.getEncryptionKeys(now).isEmpty());

        OpenPGPCertificate tampered = withUserIdCertification(api, cert,
            corrupt(userIdCertification(api, key, new Date(now.getTime() - MILLIS_PER_HOUR), null)));

        isFalse("an unverifiable newer user ID certification must not revive an expired v" + version + " key",
            tampered.getPrimaryKey().isBoundAt(now));
        isTrue("an unverifiable newer user ID certification must not revive an expired v" + version + " encryption key",
            tampered.getEncryptionKeys(now).isEmpty());
        isTrue("an unverifiable newer user ID certification must not revive an expired v" + version + " signing key",
            tampered.getSigningKeys(now).isEmpty());
    }

    private void validUserIdCertificationRevivesExpiredKey(OpenPGPApi api, int version)
        throws PGPException, IOException
    {
        if (version == PublicKeyPacket.VERSION_6)
        {
            // a v6 key's expiration lives on its Direct Key signature, a user ID certification cannot extend it
            return;
        }

        Date now = new Date();
        OpenPGPKey key = expiredKey(api, version);
        OpenPGPCertificate cert = reparse(api, key.toCertificate());

        OpenPGPCertificate renewed = withDirectKeySignature(api, cert,
            directKeySignature(api, key, new Date(now.getTime() - MILLIS_PER_HOUR)));

        isTrue("a valid newer self-signature without expiration should renew an expired v" + version + " key",
            renewed.getPrimaryKey().isBoundAt(now));
    }

    private void unverifiedDirectKeySignatureDoesNotUnbindKey(OpenPGPApi api, int version)
        throws PGPException, IOException
    {
        Date now = new Date();
        OpenPGPKey key = currentKey(api, version);
        OpenPGPCertificate cert = reparse(api, key.toCertificate());

        isTrue("test setup: v" + version + " key should be bound", cert.getPrimaryKey().isBoundAt(now));

        OpenPGPCertificate tampered = withDirectKeySignature(api, cert,
            corrupt(directKeySignature(api, key, new Date(now.getTime() - MILLIS_PER_HOUR))));

        isTrue("an unverifiable newer Direct Key signature must not unbind a v" + version + " key",
            tampered.getPrimaryKey().isBoundAt(now));
        isFalse("an unverifiable newer Direct Key signature must not remove a v" + version + " encryption key",
            tampered.getEncryptionKeys(now).isEmpty());
        isFalse("an unverifiable newer Direct Key signature must not remove a v" + version + " signing key",
            tampered.getSigningKeys(now).isEmpty());
        isFalse("an unverifiable newer Direct Key signature must not unbind a v" + version + " user ID",
            tampered.getValidUserIds(now).isEmpty());
    }

    private void unverifiedHardRevocationDoesNotRevokeKey(OpenPGPApi api, int version)
        throws PGPException, IOException
    {
        Date now = new Date();
        OpenPGPKey key = currentKey(api, version);
        OpenPGPCertificate cert = reparse(api, key.toCertificate());

        // dated at key creation, older than every genuine self-signature - a hard revocation needs no recency
        OpenPGPCertificate tampered = withDirectKeySignature(api, cert,
            corrupt(keyRevocation(api, key, key.getPrimaryKey().getCreationTime())));

        isTrue("an unverifiable hard revocation must not revoke a v" + version + " key",
            tampered.getPrimaryKey().isBoundAt(now));
        isFalse("an unverifiable hard revocation must not remove a v" + version + " encryption key",
            tampered.getEncryptionKeys(now).isEmpty());
        isTrue("an unverifiable hard revocation must not be reported as the v" + version + " key's revocation",
            tampered.getRevocation(now) == null);
    }

    private void validHardRevocationRevokesKey(OpenPGPApi api, int version)
        throws PGPException, IOException
    {
        Date now = new Date();
        OpenPGPKey key = currentKey(api, version);
        OpenPGPCertificate cert = reparse(api, key.toCertificate());

        OpenPGPCertificate revoked = withDirectKeySignature(api, cert,
            keyRevocation(api, key, key.getPrimaryKey().getCreationTime()));

        isFalse("a valid hard revocation should revoke a v" + version + " key",
            revoked.getPrimaryKey().isBoundAt(now));
        isTrue("a valid hard revocation should remove the v" + version + " encryption key",
            revoked.getEncryptionKeys(now).isEmpty());
        isTrue("a valid hard revocation should be reported as the v" + version + " key's revocation",
            revoked.getRevocation(now) != null);
    }

    private void unverifiedSubkeyBindingDoesNotUnbindSubkey(OpenPGPApi api, int version)
        throws PGPException, IOException
    {
        Date now = new Date();
        OpenPGPKey key = currentKey(api, version);
        OpenPGPCertificate cert = reparse(api, key.toCertificate());

        OpenPGPCertificate.OpenPGPComponentKey encryptionKey =
            cert.getEncryptionKeys(now).get(0);

        PGPSignatureGenerator gen = generator(api, key, PGPSignature.SUBKEY_BINDING,
            new Date(now.getTime() - MILLIS_PER_HOUR));
        PGPSignature binding = gen.generateCertification(
            cert.getPrimaryKey().getPGPPublicKey(), encryptionKey.getPGPPublicKey());

        PGPPublicKeyRing ring = cert.getPGPPublicKeyRing();
        PGPPublicKey tamperedSubkey = PGPPublicKey.addCertification(encryptionKey.getPGPPublicKey(), corrupt(binding));
        OpenPGPCertificate tampered = parse(api, PGPPublicKeyRing.insertPublicKey(ring, tamperedSubkey));

        isFalse("an unverifiable newer subkey binding must not unbind a v" + version + " encryption subkey",
            tampered.getEncryptionKeys(now).isEmpty());
    }

    private void unverifiedUserIdCertificationDoesNotUnbindUserId(OpenPGPApi api, int version)
        throws PGPException, IOException
    {
        Date now = new Date();
        OpenPGPKey key = currentKey(api, version);
        OpenPGPCertificate cert = reparse(api, key.toCertificate());

        OpenPGPCertificate tampered = withUserIdCertification(api, cert,
            corrupt(userIdCertification(api, key, new Date(now.getTime() - MILLIS_PER_HOUR), null)));

        isFalse("an unverifiable newer user ID certification must not unbind a v" + version + " user ID",
            tampered.getValidUserIds(now).isEmpty());
        isTrue("an unverifiable newer user ID certification must not unbind a v" + version + " key",
            tampered.getPrimaryKey().isBoundAt(now));
    }

    private void unverifiedUserIdCertificationDoesNotChangePreferences(OpenPGPApi api, int version)
        throws PGPException, IOException
    {
        Date now = new Date();
        OpenPGPKey key = currentKey(api, version);
        OpenPGPCertificate cert = reparse(api, key.toCertificate());

        int genuineFeatures = features(cert, now);
        int[] genuineSymmetric = symmetricPreferences(cert, now);
        isTrue("test setup: v" + version + " key should advertise SEIPDv2",
            (genuineFeatures & Features.FEATURE_SEIPD_V2) != 0);

        OpenPGPCertificate tampered = withUserIdCertification(api, cert,
            corrupt(userIdCertification(api, key, new Date(now.getTime() - MILLIS_PER_HOUR), downgradedPreferences())));

        isEquals("an unverifiable newer user ID certification must not change the v" + version + " Features",
            genuineFeatures, features(tampered, now));
        isTrue("an unverifiable newer user ID certification must not change the v" + version + " cipher preferences",
            Arrays.areEqual(genuineSymmetric, symmetricPreferences(tampered, now)));
    }

    private void validUserIdCertificationChangesPreferences(OpenPGPApi api, int version)
        throws PGPException, IOException
    {
        Date now = new Date();
        OpenPGPKey key = currentKey(api, version);
        OpenPGPCertificate cert = reparse(api, key.toCertificate());

        OpenPGPCertificate updated = withUserIdCertification(api, cert,
            userIdCertification(api, key, new Date(now.getTime() - MILLIS_PER_HOUR), downgradedPreferences()));

        isEquals("a valid newer user ID certification should supply the v" + version + " Features",
            Features.FEATURE_MODIFICATION_DETECTION, features(updated, now));
    }

    /**
     * Return the Features octet applying to the primary key, or -1 if none applies.
     */
    private int features(OpenPGPCertificate cert, Date evaluationTime)
    {
        Features features = cert.getPrimaryKey().getFeatures(evaluationTime);
        return features == null ? -1 : features.getFeatures();
    }

    /**
     * Return the symmetric cipher preferences applying to the primary key, or null if none apply.
     */
    private int[] symmetricPreferences(OpenPGPCertificate cert, Date evaluationTime)
    {
        PreferredAlgorithms preferences = cert.getPrimaryKey().getSymmetricCipherPreferences(evaluationTime);
        return preferences == null ? null : preferences.getPreferences();
    }

    private PGPSignatureSubpacketGenerator downgradedPreferences()
    {
        PGPSignatureSubpacketGenerator subpackets = new PGPSignatureSubpacketGenerator();
        subpackets.setPrimaryUserID(false, true);
        subpackets.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);
        subpackets.setPreferredSymmetricAlgorithms(false, new int[]{SymmetricKeyAlgorithmTags.AES_128});
        return subpackets;
    }

    private OpenPGPKey currentKey(OpenPGPApi api, int version)
        throws PGPException
    {
        return api.generateKey(version, new Date(currentTimeRounded().getTime() - MILLIS_PER_DAY))
            .classicKey(USER_ID)
            .build();
    }

    private OpenPGPKey expiredKey(OpenPGPApi api, int version)
        throws PGPException
    {
        return api.generateKey(version, new Date(currentTimeRounded().getTime() - BEYOND_DEFAULT_EXPIRY))
            .classicKey(USER_ID)
            .build();
    }

    private PGPSignatureGenerator generator(OpenPGPApi api, OpenPGPKey key, int type, Date creationTime)
        throws PGPException
    {
        return generator(api, key, type, creationTime, new PGPSignatureSubpacketGenerator());
    }

    private PGPSignatureGenerator generator(OpenPGPApi api, OpenPGPKey key, int type, Date creationTime,
                                            PGPSignatureSubpacketGenerator subpackets)
        throws PGPException
    {
        PGPPublicKey primary = key.getPrimaryKey().getPGPPublicKey();
        PGPPrivateKey privateKey = key.getPrimarySecretKey().unlock().getKeyPair().getPrivateKey();

        PGPSignatureGenerator gen = new PGPSignatureGenerator(
            api.getImplementation().pgpContentSignerBuilder(primary.getAlgorithm(), HashAlgorithmTags.SHA512),
            primary);
        gen.init(type, privateKey);

        subpackets.setSignatureCreationTime(true, creationTime);
        subpackets.setIssuerFingerprint(true, primary);
        gen.setHashedSubpackets(subpackets.generate());
        return gen;
    }

    private PGPSignature directKeySignature(OpenPGPApi api, OpenPGPKey key, Date creationTime)
        throws PGPException
    {
        PGPSignatureGenerator gen = generator(api, key, PGPSignature.DIRECT_KEY, creationTime);
        return gen.generateCertification(key.getPrimaryKey().getPGPPublicKey());
    }

    private PGPSignature keyRevocation(OpenPGPApi api, OpenPGPKey key, Date creationTime)
        throws PGPException
    {
        PGPSignatureSubpacketGenerator subpackets = new PGPSignatureSubpacketGenerator();
        subpackets.setRevocationReason(true, RevocationReasonTags.NO_REASON, "");
        PGPSignatureGenerator gen = generator(api, key, PGPSignature.KEY_REVOCATION, creationTime, subpackets);
        return gen.generateCertification(key.getPrimaryKey().getPGPPublicKey());
    }

    private PGPSignature userIdCertification(OpenPGPApi api, OpenPGPKey key, Date creationTime,
                                             PGPSignatureSubpacketGenerator subpackets)
        throws PGPException
    {
        PGPSignatureGenerator gen = generator(api, key, PGPSignature.POSITIVE_CERTIFICATION, creationTime,
            subpackets == null ? new PGPSignatureSubpacketGenerator() : subpackets);
        return gen.generateCertification(USER_ID, key.getPrimaryKey().getPGPPublicKey());
    }

    private OpenPGPCertificate withDirectKeySignature(OpenPGPApi api, OpenPGPCertificate cert, PGPSignature signature)
        throws IOException
    {
        PGPPublicKeyRing ring = cert.getPGPPublicKeyRing();
        PGPPublicKey primary = PGPPublicKey.addCertification(ring.getPublicKey(), signature);
        return parse(api, PGPPublicKeyRing.insertPublicKey(ring, primary));
    }

    private OpenPGPCertificate withUserIdCertification(OpenPGPApi api, OpenPGPCertificate cert, PGPSignature signature)
        throws IOException
    {
        PGPPublicKeyRing ring = cert.getPGPPublicKeyRing();
        PGPPublicKey primary = PGPPublicKey.addCertification(ring.getPublicKey(), USER_ID, signature);
        return parse(api, PGPPublicKeyRing.insertPublicKey(ring, primary));
    }

    private OpenPGPCertificate reparse(OpenPGPApi api, OpenPGPCertificate cert)
        throws IOException
    {
        return api.readKeyOrCertificate().parseCertificate(cert.getEncoded());
    }

    private OpenPGPCertificate parse(OpenPGPApi api, PGPPublicKeyRing ring)
        throws IOException
    {
        // re-parse from the wire, as a relying party would
        return api.readKeyOrCertificate().parseCertificate(ring.getEncoded());
    }

    /**
     * Return a copy of the signature with the last octet of its signature value flipped: well-formed, naming
     * the genuine issuer, and not verifying.
     */
    private PGPSignature corrupt(PGPSignature signature)
        throws IOException
    {
        byte[] encoding = signature.getEncoded();
        encoding[encoding.length - 1] ^= 0x01;

        Object o = new BcPGPObjectFactory(encoding).nextObject();
        return ((PGPSignatureList)o).get(0);
    }

    public static void main(String[] args)
    {
        runTest(new OpenPGPUnverifiedSelfSignatureTest());
    }
}
