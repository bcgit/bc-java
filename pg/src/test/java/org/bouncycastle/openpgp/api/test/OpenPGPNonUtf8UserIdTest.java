package org.bouncycastle.openpgp.api.test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * Regression test: a user-id that is not valid UTF-8 binds its key.
 * <p>
 * RFC 9580, section 5.11: the user-id is "intended to be" UTF-8, so older keys carry user-ids in
 * other encodings, certified over the bytes of their user-id packet. Without a Direct Key
 * signature, a v4 primary key is bound by such a certification, which other implementations
 * verify over those bytes. The certificate read user-ids as strings, skipping one that does not
 * decode as UTF-8, and verified certifications over the string's UTF-8 encoding, so the key was
 * unbound and offered no signing key although its certification verifies.
 * <p>
 * The control attaches to the same user-id a certification made over a different encoding of
 * its text, which must not bind it.
 */
public class OpenPGPNonUtf8UserIdTest
    extends APITest
{
    private static final long MILLIS_PER_DAY = 24 * 60 * 60 * 1000L;
    private static final long MILLIS_PER_HOUR = 60 * 60 * 1000L;

    private static final String USER_ID_TEXT = "Éamonn <eamonn@example.org>";

    // ISO-8859-1: 0xC9 starts a two-byte UTF-8 sequence, which 'a' cannot continue
    private static final byte[] LATIN1_USER_ID = Strings.toByteArray(USER_ID_TEXT);

    public String getName()
    {
        return "OpenPGPNonUtf8UserIdTest";
    }

    protected void performTestWith(OpenPGPApi api)
        throws PGPException, IOException
    {
        nonUtf8UserIdBindsKey(api);
        certificationOverAnotherEncodingDoesNotBindKey(api);
    }

    private void nonUtf8UserIdBindsKey(OpenPGPApi api)
        throws PGPException, IOException
    {
        Date now = new Date();
        OpenPGPKey key = signingKey(api);

        OpenPGPCertificate cert = certificateWithUserId(api, key,
            certification(api, key, LATIN1_USER_ID, new Date(now.getTime() - MILLIS_PER_HOUR)));

        List userIds = cert.getAllUserIds();
        isEquals("the non-UTF-8 user-id should be a component of the certificate", 1, userIds.size());
        OpenPGPCertificate.OpenPGPUserId userId = (OpenPGPCertificate.OpenPGPUserId)userIds.get(0);
        isTrue("the user-id should keep the bytes of its packet",
            Arrays.areEqual(LATIN1_USER_ID, userId.getRawUserId()));
        isTrue("the user-id text should be decoded with malformed input replaced",
            userId.getUserId().indexOf('�') >= 0);
        isTrue("a key bound by a non-UTF-8 user-id should be bound", cert.getPrimaryKey().isBoundAt(now));
        isEquals("a key bound by a non-UTF-8 user-id should be a signing key", 1, cert.getSigningKeys(now).size());
    }

    private void certificationOverAnotherEncodingDoesNotBindKey(OpenPGPApi api)
        throws PGPException, IOException
    {
        Date now = new Date();
        OpenPGPKey key = signingKey(api);

        OpenPGPCertificate cert = certificateWithUserId(api, key,
            certification(api, key, Strings.toUTF8ByteArray(USER_ID_TEXT), new Date(now.getTime() - MILLIS_PER_HOUR)));

        isFalse("a certification over another encoding of the user-id should not bind the key",
            cert.getPrimaryKey().isBoundAt(now));
        isTrue("a certification over another encoding of the user-id should leave no signing key",
            cert.getSigningKeys(now).isEmpty());
    }

    private OpenPGPKey signingKey(OpenPGPApi api)
        throws PGPException
    {
        return api.generateKey(PublicKeyPacket.VERSION_4, new Date(currentTimeRounded().getTime() - MILLIS_PER_DAY))
            .signOnlyKey()
            .build();
    }

    private PGPSignature certification(OpenPGPApi api, OpenPGPKey key, byte[] certifiedBytes, Date creationTime)
        throws PGPException
    {
        PGPKeyPair primary = key.getPrimarySecretKey().unlock().getKeyPair();
        PGPSignatureGenerator gen = new PGPSignatureGenerator(
            api.getImplementation().pgpContentSignerBuilder(primary.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA512),
            primary.getPublicKey());
        gen.init(PGPSignature.POSITIVE_CERTIFICATION, primary.getPrivateKey());

        PGPSignatureSubpacketGenerator subpackets = new PGPSignatureSubpacketGenerator();
        subpackets.setSignatureCreationTime(true, creationTime);
        subpackets.setIssuerFingerprint(true, primary.getPublicKey());
        subpackets.setKeyFlags(true, KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA);
        gen.setHashedSubpackets(subpackets.generate());
        return gen.generateCertification(certifiedBytes, primary.getPublicKey());
    }

    /**
     * The bare primary key, with no Direct Key signature, carrying the Latin-1 user-id and the
     * given certification of it, re-parsed from the wire as a relying party would.
     */
    private OpenPGPCertificate certificateWithUserId(OpenPGPApi api, OpenPGPKey key, PGPSignature certification)
        throws PGPException, IOException
    {
        PGPPublicKey bare = new PGPPublicKey(key.getPrimaryKey().getPGPPublicKey().getPublicKeyPacket(),
            api.getImplementation().keyFingerPrintCalculator());
        List keys = new ArrayList();
        keys.add(PGPPublicKey.addCertification(bare, LATIN1_USER_ID, certification));
        return api.readKeyOrCertificate().parseCertificate(new PGPPublicKeyRing(keys).getEncoded());
    }

    public static void main(String[] args)
    {
        runTest(new OpenPGPNonUtf8UserIdTest());
    }
}
