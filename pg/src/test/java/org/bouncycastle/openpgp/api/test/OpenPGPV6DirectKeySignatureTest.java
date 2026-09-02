package org.bouncycastle.openpgp.api.test;

import java.io.IOException;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.util.Arrays;

/**
 * Regression test: RFC 9580, section 5.2.3.10 states that "An implementation MUST ensure that a valid
 * Direct Key signature is present before using a version 6 key. This prevents certain attacks where
 * an adversary strips a self-signature specifying a Key Expiration Time or certain preferences."
 * <p>
 * A version 6 certificate carries the key expiration, the features and the algorithm preferences on the
 * Direct Key signature - that is what the RFC recommends and what {@code OpenPGPKeyGenerator} produces -
 * while the User ID self-signature carries none of them. Falling back to the User ID binding when the
 * Direct Key signature is absent therefore let an adversary remove one signature packet from a published
 * certificate and silently drop the key expiration along with it: the primary key fingerprint is unchanged,
 * so a relying party that pins the key still treats it as the same key, only now one that never expires.
 * The certificate grammar says the same structurally - the Direct Key signature is mandatory in the version 6
 * structure of section 10.1.1 and optional in the version 4 one of section 10.1.3.
 * <p>
 * The fallback remains correct for a version 4 certificate, where the key expiration legitimately lives on
 * the User ID self-signature (RFC 9580, section 10.1.3, where the Direct Key signature is the optional one).
 */
public class OpenPGPV6DirectKeySignatureTest
    extends APITest
{
    private static final long MILLIS_PER_DAY = 24 * 60 * 60 * 1000L;
    // OpenPGPKeyGenerator gives a generated key a default expiration of 5 years.
    private static final long BEYOND_DEFAULT_EXPIRY = 6 * 365 * MILLIS_PER_DAY;

    public String getName()
    {
        return "OpenPGPV6DirectKeySignatureTest";
    }

    protected void performTestWith(OpenPGPApi api)
        throws PGPException, IOException
    {
        Date creationTime = currentTimeRounded();
        Date inWindow = new Date(creationTime.getTime() + MILLIS_PER_DAY);
        Date afterExpiry = new Date(creationTime.getTime() + BEYOND_DEFAULT_EXPIRY);

        testIntactVersion6Certificate(api, creationTime, inWindow, afterExpiry);
        testStrippedVersion6CertificateIsRefused(api, creationTime, inWindow, afterExpiry);
        testStrippedVersion4CertificateStillFallsBackToUserId(api, creationTime, inWindow);
    }

    /**
     * Compatibility: a version 6 certificate that carries its Direct Key signature is usable inside its
     * validity window, and its expiration is honoured once passed.
     */
    private void testIntactVersion6Certificate(OpenPGPApi api, Date creationTime, Date inWindow, Date afterExpiry)
        throws PGPException, IOException
    {
        OpenPGPCertificate cert = certificate(api, PublicKeyPacket.VERSION_6, creationTime);

        isTrue("test setup: a generated v6 certificate must carry a Direct Key signature",
            hasDirectKeySignature(cert));

        isTrue("intact v6 primary key must be bound inside its validity window",
            cert.getPrimaryKey().isBoundAt(inWindow));
        isTrue("intact v6 certificate must offer an encryption key inside its validity window",
            !cert.getEncryptionKeys(inWindow).isEmpty());
        isTrue("intact v6 certificate must offer a signing key inside its validity window",
            !cert.getSigningKeys(inWindow).isEmpty());

        isFalse("intact v6 primary key must not be bound after its expiration",
            cert.getPrimaryKey().isBoundAt(afterExpiry));
        isTrue("intact v6 certificate must offer no encryption key after its expiration",
            cert.getEncryptionKeys(afterExpiry).isEmpty());
        isTrue("intact v6 certificate must offer no signing key after its expiration",
            cert.getSigningKeys(afterExpiry).isEmpty());
    }

    /**
     * Removing the single Direct Key signature packet must not leave a usable version 6 certificate -
     * neither inside the window the removed signature described, nor beyond the expiration it carried.
     */
    private void testStrippedVersion6CertificateIsRefused(OpenPGPApi api, Date creationTime, Date inWindow, Date afterExpiry)
        throws PGPException, IOException
    {
        OpenPGPCertificate cert = certificate(api, PublicKeyPacket.VERSION_6, creationTime);
        OpenPGPCertificate stripped = api.readKeyOrCertificate()
            .parseCertificate(withoutDirectKeySignatures(cert));

        isFalse("test setup: no Direct Key signature may remain on the stripped certificate",
            hasDirectKeySignature(stripped));
        isTrue("test setup: stripping the Direct Key signature must not change the primary key fingerprint",
            Arrays.areEqual(cert.getFingerprint(), stripped.getFingerprint()));
        isFalse("test setup: the stripped certificate must still carry its user id binding",
            stripped.getPrimaryKey().getUserIDs().isEmpty());

        isFalse("v6 primary key without a Direct Key signature must not be bound",
            stripped.getPrimaryKey().isBoundAt(inWindow));
        isTrue("v6 certificate without a Direct Key signature must offer no encryption key",
            stripped.getEncryptionKeys(inWindow).isEmpty());
        isTrue("v6 certificate without a Direct Key signature must offer no signing key",
            stripped.getSigningKeys(inWindow).isEmpty());

        // The reported downgrade: the key expiration lived only on the removed signature.
        isFalse("stripping the Direct Key signature must not resurrect an expired v6 primary key",
            stripped.getPrimaryKey().isBoundAt(afterExpiry));
        isTrue("stripping the Direct Key signature must not resurrect an expired v6 encryption subkey",
            stripped.getEncryptionKeys(afterExpiry).isEmpty());
        isTrue("stripping the Direct Key signature must not resurrect an expired v6 signing subkey",
            stripped.getSigningKeys(afterExpiry).isEmpty());
    }

    /**
     * Compatibility: for a version 4 certificate the User ID self-signature is the legitimate carrier of the
     * key-wide metadata, so a version 4 certificate with no Direct Key signature must remain fully usable.
     */
    private void testStrippedVersion4CertificateStillFallsBackToUserId(OpenPGPApi api, Date creationTime, Date inWindow)
        throws PGPException, IOException
    {
        OpenPGPCertificate cert = certificate(api, PublicKeyPacket.VERSION_4, creationTime);
        OpenPGPCertificate stripped = api.readKeyOrCertificate()
            .parseCertificate(withoutDirectKeySignatures(cert));

        isFalse("test setup: no Direct Key signature may remain on the stripped certificate",
            hasDirectKeySignature(stripped));

        isTrue("v4 primary key without a Direct Key signature must stay bound through its user id",
            stripped.getPrimaryKey().isBoundAt(inWindow));
        isTrue("v4 certificate without a Direct Key signature must still offer an encryption key",
            !stripped.getEncryptionKeys(inWindow).isEmpty());
        isTrue("v4 certificate without a Direct Key signature must still offer a signing key",
            !stripped.getSigningKeys(inWindow).isEmpty());
    }

    private OpenPGPCertificate certificate(OpenPGPApi api, int version, Date creationTime)
        throws PGPException, IOException
    {
        OpenPGPKey key = api.generateKey(version, creationTime)
            .classicKey("Alice <alice@example.com>")
            .build();

        // re-parse from the wire, as a relying party would
        return api.readKeyOrCertificate().parseCertificate(key.toCertificate().getEncoded());
    }

    /**
     * Return the encoding of the given certificate with every Direct Key signature on the primary key removed.
     */
    private byte[] withoutDirectKeySignatures(OpenPGPCertificate cert)
        throws IOException
    {
        PGPPublicKeyRing ring = cert.getPGPPublicKeyRing();
        PGPPublicKey primaryKey = ring.getPublicKey();
        PGPPublicKey stripped = primaryKey;

        for (Iterator<PGPSignature> it = primaryKey.getKeySignatures(); it.hasNext(); )
        {
            PGPSignature keySignature = it.next();
            if (keySignature.getSignatureType() == PGPSignature.DIRECT_KEY)
            {
                PGPPublicKey next = PGPPublicKey.removeCertification(stripped, keySignature);
                if (next != null)
                {
                    stripped = next;
                }
            }
        }

        return PGPPublicKeyRing.insertPublicKey(ring, stripped).getEncoded();
    }

    private boolean hasDirectKeySignature(OpenPGPCertificate cert)
    {
        for (Iterator<PGPSignature> it = cert.getPGPPublicKeyRing().getPublicKey().getKeySignatures(); it.hasNext(); )
        {
            if (it.next().getSignatureType() == PGPSignature.DIRECT_KEY)
            {
                return true;
            }
        }
        return false;
    }

    public static void main(String[] args)
    {
        runTest(new OpenPGPV6DirectKeySignatureTest());
    }
}
