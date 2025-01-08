package org.bouncycastle.openpgp.api.test;

import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.bcpg.test.AbstractPacketTest;
import org.bouncycastle.openpgp.OpenPGPTestKeys;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPApi;

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
    }

    private void performTestWith(OpenPGPApi api)
            throws PGPException, IOException
    {
        unmodifiedKeyTest(api);
        addUserIdTest(api);
        changePassphraseNoAEADTest(api);
        changePassphraseAEADTest(api);
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
        isNull(key.getPrimaryUserId());

        key = api.editKey(key)
                .addUserId("Alice <alice@example.com>", null)
                .done();

        isEquals("Alice <alice@example.com>", key.getPrimaryUserId().getUserId());
    }

    private void changePassphraseNoAEADTest(OpenPGPApi api)
            throws IOException
    {
        OpenPGPKey key = api.readKeyOrCertificate().parseKey(OpenPGPTestKeys.V6_KEY);
        isFalse(key.getPrimarySecretKey().isLocked());

        key = api.editKey(key)
                .changePassphrase(key.getPrimaryKey(), null, "sw0rdf1sh".toCharArray(), false)
                .done();
        isTrue(key.getPrimarySecretKey().isLocked());
        isTrue(key.getPrimarySecretKey().isPassphraseCorrect("sw0rdf1sh".toCharArray()));
        isEquals(SecretKeyPacket.USAGE_SHA1, key.getPrimarySecretKey().getPGPSecretKey().getS2KUsage());
    }

    private void changePassphraseAEADTest(OpenPGPApi api)
            throws IOException
    {
        OpenPGPKey key = api.readKeyOrCertificate().parseKey(OpenPGPTestKeys.V6_KEY);
        isFalse(key.getPrimarySecretKey().isLocked());

        key = api.editKey(key)
                .changePassphrase(key.getPrimaryKey(), null, "sw0rdf1sh".toCharArray(), true)
                .done();
        isTrue(key.getPrimarySecretKey().isLocked());
        isTrue(key.getPrimarySecretKey().isPassphraseCorrect("sw0rdf1sh".toCharArray()));
        isEquals(SecretKeyPacket.USAGE_AEAD, key.getPrimarySecretKey().getPGPSecretKey().getS2KUsage());
    }

    public static void main(String[] args)
    {
        runTest(new OpenPGPKeyEditorTest());
    }
}
