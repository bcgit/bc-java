package org.bouncycastle.openpgp.api.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.bcpg.sig.RevocationReasonTags;
import org.bouncycastle.openpgp.OpenPGPTestKeys;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.SignatureParameters;
import org.bouncycastle.openpgp.api.SignatureSubpacketsFunction;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;

public class OpenPGPKeyEditorTest
    extends APITest
{

    @Override
    public String getName()
    {
        return "OpenPGPKeyEditorTest";
    }

    protected void performTestWith(OpenPGPApi api)
        throws PGPException, IOException
    {
        doNothingTest(api);

        addUserIdTest(api);
        softRevokeUserIdTest(api);
        hardRevokeUserIdTest(api);

        addEncryptionSubkeyTest(api);
        revokeEncryptionSubkeyTest(api);

        addSigningSubkeyTest(api);
        revokeSigningSubkeyTest(api);

        extendExpirationTimeTest(api);
        revokeCertificateTest(api);

        changePassphraseUnprotectedToCFBTest(api);
        changePassphraseUnprotectedToAEADTest(api);

        ignoreInvalidRevocationSignatureTest(api);
    }

    private void doNothingTest(OpenPGPApi api)
        throws PGPException
    {
        OpenPGPKey key = api.generateKey()
            .ed25519x25519Key("Alice <alice@example.com>")
            .build();
        OpenPGPKey editedKey = api.editKey(key)
            .done();

        isTrue("Key was not changed, so the reference MUST be the same",
            key == editedKey);
    }

    private void addUserIdTest(OpenPGPApi api)
        throws IOException, PGPException
    {
        OpenPGPKey key = api.readKeyOrCertificate()
            .parseKey(OpenPGPTestKeys.V6_KEY);
        isNull("Expect primary user-id to be null", key.getPrimaryUserId());

        key = api.editKey(key)
            .addUserId("Alice <alice@example.com>")
            .done();

        isEquals("Expect the new user-id to be primary now",
            "Alice <alice@example.com>", key.getPrimaryUserId().getUserId());
    }

    private void softRevokeUserIdTest(OpenPGPApi api)
        throws IOException, PGPException
    {
        OpenPGPKey key = api.readKeyOrCertificate()
            .parseKey(OpenPGPTestKeys.ALICE_KEY);
        final Date now = currentTimeRounded();
        Date oneHourAgo = new Date(now.getTime() - (1000 * 60 * 60));
        OpenPGPCertificate.OpenPGPUserId userId = key.getPrimaryUserId(now);
        isNotNull(userId);
        isTrue(userId.isBound());
        isEquals("Alice Lovelace <alice@openpgp.example>", userId.getUserId());

        key = api.editKey(key)
            .revokeIdentity(userId, new SignatureParameters.Callback()
            {
                @Override
                public SignatureParameters apply(SignatureParameters parameters)
                {
                    parameters.setSignatureCreationTime(now);
                    parameters.setHashedSubpacketsFunction(new SignatureSubpacketsFunction()
                    {
                        @Override
                        public PGPSignatureSubpacketGenerator apply(PGPSignatureSubpacketGenerator subpackets)
                        {
                            subpackets.setRevocationReason(true, RevocationReasonTags.USER_NO_LONGER_VALID, "");
                            return subpackets;
                        }
                    });
                    return parameters;
                }
            })
            .done();
        isTrue(key.getPrimaryUserId().isBoundAt(oneHourAgo));
        isFalse(key.getPrimaryUserId().isBoundAt(now));
    }

    private void hardRevokeUserIdTest(OpenPGPApi api)
        throws IOException, PGPException
    {
        OpenPGPKey key = api.readKeyOrCertificate()
            .parseKey(OpenPGPTestKeys.ALICE_KEY);
        final Date now = currentTimeRounded();
        Date oneHourAgo = new Date(now.getTime() - (1000 * 60 * 60));
        OpenPGPCertificate.OpenPGPUserId userId = key.getPrimaryUserId(now);
        isNotNull(userId);
        isTrue(userId.isBound());
        isEquals("Alice Lovelace <alice@openpgp.example>", userId.getUserId());

        key = api.editKey(key)
            .revokeIdentity(userId, new SignatureParameters.Callback()
            {
                @Override
                public SignatureParameters apply(SignatureParameters parameters)
                {
                    parameters.setSignatureCreationTime(now);
                    // no reason -> hard revocation
                    return parameters;
                }
            })
            .done();
        isFalse(key.getPrimaryUserId().isBoundAt(oneHourAgo));
        isFalse(key.getPrimaryUserId().isBoundAt(now));
    }

    private void addEncryptionSubkeyTest(OpenPGPApi api)
        throws IOException, PGPException
    {
        OpenPGPKey key = api.readKeyOrCertificate().parseKey(OpenPGPTestKeys.V6_KEY);
        isEquals(1, key.getEncryptionKeys().size());

        key = api.editKey(key)
            .addEncryptionSubkey()
            .done();

        isEquals(2, key.getEncryptionKeys().size());
    }

    private void revokeEncryptionSubkeyTest(OpenPGPApi api)
        throws IOException, PGPException
    {
        OpenPGPKey key = api.readKeyOrCertificate().parseKey(OpenPGPTestKeys.V6_KEY);
        OpenPGPCertificate.OpenPGPComponentKey encryptionSubkey = key.getEncryptionKeys().get(0);

        key = api.editKey(key)
            .revokeComponentKey(encryptionSubkey)
            .done();

        isEquals(0, key.getEncryptionKeys().size());
    }

    private void addSigningSubkeyTest(OpenPGPApi api)
        throws IOException, PGPException
    {
        OpenPGPKey key = api.readKeyOrCertificate().parseKey(OpenPGPTestKeys.V6_KEY);
        isEquals(1, key.getSigningKeys().size());

        key = api.editKey(key)
            .addSigningSubkey()
            .done();

        isEquals(2, key.getSigningKeys().size());
    }

    private void revokeSigningSubkeyTest(OpenPGPApi api)
        throws PGPException
    {
        OpenPGPKey key = api.generateKey()
            .classicKey(null)
            .build();
        isEquals(1, key.getSigningKeys().size());

        OpenPGPCertificate.OpenPGPComponentKey signingKey = key.getSigningKeys().get(0);
        key = api.editKey(key)
            .revokeComponentKey(signingKey)
            .done();
        isEquals(0, key.getSigningKeys().size());
    }

    private void extendExpirationTimeTest(OpenPGPApi api)
        throws PGPException
    {
        Date n0 = currentTimeRounded();
        OpenPGPKey key = api.generateKey(n0, false)
            .classicKey(null)
            .build();
        isEquals("Default key generation MUST set expiration time of +5years",
            key.getExpirationTime().getTime(), n0.getTime() + 5L * 31536000 * 1000);

        final Date n1 = new Date(n0.getTime() + 1000); // 1 sec later

        key = api.editKey(key)
            .addDirectKeySignature(new SignatureParameters.Callback()
            {
                @Override
                public SignatureParameters apply(SignatureParameters parameters)
                {
                    parameters.setSignatureCreationTime(n1);
                    parameters.setHashedSubpacketsFunction(new SignatureSubpacketsFunction()
                    {
                        @Override
                        public PGPSignatureSubpacketGenerator apply(PGPSignatureSubpacketGenerator subpackets)
                        {
                            subpackets.setKeyExpirationTime(8L * 31536000);
                            return subpackets;
                        }
                    });
                    return parameters;
                }
            })
            .done();

        isEquals("At n1, the expiration time of the key MUST have changed to n0+8years",
            key.getExpirationTime(n1).getTime(), n0.getTime() + 8L * 31536000 * 1000);
    }

    private void revokeCertificateTest(OpenPGPApi api)
        throws IOException, PGPException
    {
        OpenPGPKey key = api.readKeyOrCertificate().parseKey(OpenPGPTestKeys.V6_KEY);

        key = api.editKey(key)
            .revokeKey()
            .done();

        isEquals(0, key.getEncryptionKeys().size());
    }

    private void changePassphraseUnprotectedToCFBTest(OpenPGPApi api)
        throws IOException, PGPException
    {
        OpenPGPKey key = api.readKeyOrCertificate().parseKey(OpenPGPTestKeys.V6_KEY);
        isFalse(key.getPrimarySecretKey().isLocked());

        key = api.editKey(key)
            .changePassphrase(key.getPrimaryKey().getKeyIdentifier(), (char[]) null, "sw0rdf1sh".toCharArray(), false)
            .done();
        isTrue("Expect key to be locked", key.getPrimarySecretKey().isLocked());
        isTrue("Expect sw0rdf1sh to be the correct passphrase",
            key.getPrimarySecretKey().isPassphraseCorrect("sw0rdf1sh".toCharArray()));
        isEquals("Expect use of USAGE_CHECKSUM for key protection",
            SecretKeyPacket.USAGE_SHA1, key.getPrimarySecretKey().getPGPSecretKey().getS2KUsage());
    }

    private void changePassphraseUnprotectedToAEADTest(OpenPGPApi api)
        throws IOException, PGPException
    {
        OpenPGPKey key = api.readKeyOrCertificate().parseKey(OpenPGPTestKeys.V6_KEY);
        isFalse("Expect key to be unprotected", key.getPrimarySecretKey().isLocked());

        key = api.editKey(key)
            .changePassphrase(key.getPrimaryKey().getKeyIdentifier(), (char[]) null, "sw0rdf1sh".toCharArray(), true)
            .done();
        isTrue("Expect key to be locked after changing passphrase",
            key.getPrimarySecretKey().isLocked());
        isTrue("Expect sw0rdf1sh to be the correct passphrase using AEAD",
            key.getPrimarySecretKey().isPassphraseCorrect("sw0rdf1sh".toCharArray()));
        isEquals("Expect use of AEAD for key protection",
            SecretKeyPacket.USAGE_AEAD, key.getPrimarySecretKey().getPGPSecretKey().getS2KUsage());
    }

    private void ignoreInvalidRevocationSignatureTest(OpenPGPApi api)
            throws IOException
    {
        OpenPGPKey key = api.readKeyOrCertificate().parseKey(OpenPGPTestKeys.ALICE_KEY);
        isNull("Test key MUST NOT be revoked", key.getRevocation());

        // is usable
        for (Iterator<OpenPGPCertificate.OpenPGPCertificateComponent> it = key.getComponents().iterator(); it.hasNext(); )
        {
            OpenPGPCertificate.OpenPGPCertificateComponent c = it.next();
            isTrue("All components MUST be validly bound BEFORE injecting broken revocation", c.isBound());
        }

        // eddsa_sig_s = 01010101... This is a cryptographically invalid revocation signature
        String forgedRevocation = "8878042016080020162104eb85bb5fa33a75e15e944e63f231550c4f47e38e05025da5a43b021d00000a0910f231550c4f47e38e80650100c0f6e91914a445182a2855c5680d59b14da1cb51794883d4cf8767fbcf323d2a00ff0101010101010101010101010101010101010101010101010101010101010101";
        ByteArrayInputStream bIn = new ByteArrayInputStream(org.bouncycastle.util.encoders.Hex.decode(forgedRevocation));
        BCPGInputStream pIn = new BCPGInputStream(bIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPSignatureList sigList = (PGPSignatureList) objFac.nextObject();

        PGPSecretKeyRing sKeyRing = key.getPGPSecretKeyRing();
        PGPPublicKey primaryKey = sKeyRing.getPublicKey();
        primaryKey = PGPPublicKey.addCertification(primaryKey, sigList.get(0));
        sKeyRing = PGPSecretKeyRing.insertOrReplacePublicKey(sKeyRing, primaryKey);
        OpenPGPKey improperlyRevokedKey = new OpenPGPKey(sKeyRing);

        isNull("Improperly revoked key still MUST NOT be revoked", key.getRevocation());

        // is still usable
        for (Iterator<OpenPGPCertificate.OpenPGPCertificateComponent> it = improperlyRevokedKey.getComponents().iterator(); it.hasNext(); )
        {
            OpenPGPCertificate.OpenPGPCertificateComponent c = it.next();
            isTrue("All components MUST be validly bound AFTER injecting broken revocation", c.isBound());
        }
    }

    public static void main(String[] args)
    {
        runTest(new OpenPGPKeyEditorTest());
    }
}
