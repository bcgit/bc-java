package org.bouncycastle.openpgp.api.test;

import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.bcpg.test.AbstractPacketTest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.OpenPGPTestKeys;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPApi;
import org.bouncycastle.openpgp.api.jcajce.JcaOpenPGPApi;

import java.io.IOException;

public class OpenPGPKeyEditorTest
    extends AbstractPacketTest
{

    @Override
    public String getName()
    {
        return "OpenPGPKeyEditorTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        OpenPGPApi api = new BcOpenPGPApi();
        performTestWith(api);

        api = new JcaOpenPGPApi(new BouncyCastleProvider());
        performTestWith(api);
    }

    private void performTestWith(OpenPGPApi api)
            throws PGPException, IOException
    {
        unmodifiedKeyTest(api);
        addUserIdTest(api);
        changePassphraseUnprotectedToCFBTest(api);
        changePassphraseUnprotectedToAEADTest(api);
    }

    private void unmodifiedKeyTest(OpenPGPApi api)
            throws PGPException
    {
        OpenPGPKey key = api.generateKey()
                .ed25519x25519Key("Alice <alice@example.com>", null);
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
                .addUserId("Alice <alice@example.com>", null)
                .done();

        isEquals("Expect the new user-id to be primary now",
                "Alice <alice@example.com>", key.getPrimaryUserId().getUserId());
    }

    private void changePassphraseUnprotectedToCFBTest(OpenPGPApi api)
            throws IOException
    {
        OpenPGPKey key = api.readKeyOrCertificate().parseKey(OpenPGPTestKeys.V6_KEY);
        isFalse(key.getPrimarySecretKey().isLocked());

        key = api.editKey(key)
                .changePassphrase(key.getPrimaryKey(), null, "sw0rdf1sh".toCharArray(), false)
                .done();
        isTrue("Expect key to be locked", key.getPrimarySecretKey().isLocked());
        isTrue("Expect sw0rdf1sh to be the correct passphrase",
                key.getPrimarySecretKey().isPassphraseCorrect("sw0rdf1sh".toCharArray()));
        isEquals("Expect use of USAGE_CHECKSUM for key protection",
                SecretKeyPacket.USAGE_SHA1, key.getPrimarySecretKey().getPGPSecretKey().getS2KUsage());
    }

    private void changePassphraseUnprotectedToAEADTest(OpenPGPApi api)
            throws IOException
    {
        OpenPGPKey key = api.readKeyOrCertificate().parseKey(OpenPGPTestKeys.V6_KEY);
        isFalse("Expect key to be unprotected", key.getPrimarySecretKey().isLocked());

        key = api.editKey(key)
                .changePassphrase(key.getPrimaryKey(), null, "sw0rdf1sh".toCharArray(), true)
                .done();
        isTrue("Expect key to be locked after changing passphrase",
                key.getPrimarySecretKey().isLocked());
        isTrue("Expect sw0rdf1sh to be the correct passphrase using AEAD",
                key.getPrimarySecretKey().isPassphraseCorrect("sw0rdf1sh".toCharArray()));
        isEquals("Expect use of AEAD for key protection",
                SecretKeyPacket.USAGE_AEAD, key.getPrimarySecretKey().getPGPSecretKey().getS2KUsage());
    }

    public static void main(String[] args)
    {
        runTest(new OpenPGPKeyEditorTest());
    }
}
