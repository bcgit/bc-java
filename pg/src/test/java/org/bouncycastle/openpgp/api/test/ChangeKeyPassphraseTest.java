package org.bouncycastle.openpgp.api.test;

import java.io.IOException;

import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.openpgp.OpenPGPTestKeys;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.OpenPGPKey;

public class ChangeKeyPassphraseTest
        extends APITest
{
    @Override
    protected void performTestWith(OpenPGPApi api)
            throws PGPException, IOException
    {
        if (System.getProperty("java.version").indexOf("1.5.") < 0)
        {
            removeAEADPassphrase(api);
            addAEADPassphrase(api);
            changeAEADPassphrase(api);

            testChangingCFBPassphrase(api);
        }
    }

    private void removeAEADPassphrase(OpenPGPApi api)
            throws IOException, PGPException {
        OpenPGPKey key = api.readKeyOrCertificate()
                .parseKey(OpenPGPTestKeys.V6_KEY_LOCKED);

        OpenPGPKey.OpenPGPSecretKey secretKey = key.getPrimarySecretKey();
        isTrue("Expect test key to be locked initially", secretKey.isLocked());
        OpenPGPKey.OpenPGPPrivateKey privateKey = secretKey.unlock(OpenPGPTestKeys.V6_KEY_LOCKED_PASSPHRASE.toCharArray());
        OpenPGPKey.OpenPGPSecretKey unlocked = privateKey.removePassphrase();
        isFalse("Expect key to be unlocked after unlocking - duh", unlocked.isLocked());

        OpenPGPKey expected = api.readKeyOrCertificate().parseKey(OpenPGPTestKeys.V6_KEY);
        isEncodingEqual("Expect unlocked key encoding to equal the unprotected test vector",
                expected.getPrimarySecretKey().getPGPSecretKey().getEncoded(),
                unlocked.getPGPSecretKey().getEncoded());
    }

    private void addAEADPassphrase(OpenPGPApi api)
            throws IOException, PGPException
    {
        OpenPGPKey key = api.readKeyOrCertificate().parseKey(OpenPGPTestKeys.V6_KEY);
        OpenPGPKey.OpenPGPSecretKey secretKey = key.getPrimarySecretKey();
        isFalse("Expect unlocked test vector to be unlocked", secretKey.isLocked());

        OpenPGPKey.OpenPGPPrivateKey privateKey = secretKey.unlock();
        OpenPGPKey.OpenPGPSecretKey locked = privateKey.changePassphrase(
                "sw0rdf1sh".toCharArray(),
                api.getImplementation(),
                true);
        isTrue("Expect test key to be locked after locking", locked.isLocked());
        isEquals("Expect locked key to use AEAD",
                SecretKeyPacket.USAGE_AEAD, locked.getPGPSecretKey().getS2KUsage());
        isTrue("Expect key to be unlockable with used passphrase",
                locked.isPassphraseCorrect("sw0rdf1sh".toCharArray()));
    }

    private void changeAEADPassphrase(OpenPGPApi api)
            throws IOException, PGPException
    {
        OpenPGPKey key = api.readKeyOrCertificate()
                .parseKey(OpenPGPTestKeys.V6_KEY_LOCKED);

        OpenPGPKey.OpenPGPSecretKey secretKey = key.getPrimarySecretKey();
        isTrue("Expect locked test vector to be locked initially",
                secretKey.isLocked());
        OpenPGPKey.OpenPGPPrivateKey privateKey = secretKey.unlock(OpenPGPTestKeys.V6_KEY_LOCKED_PASSPHRASE.toCharArray());
        OpenPGPKey.OpenPGPSecretKey relocked = privateKey.changePassphrase("sw0rdf1sh".toCharArray());
        isTrue("Expect key to still be locked after changing passphrase", relocked.isLocked());
        isTrue("Expect key to be unlockable with used passphrase",
                relocked.isPassphraseCorrect("sw0rdf1sh".toCharArray()));
        isEquals("Expect re-locked key to use AEAD",
                relocked.getPGPSecretKey().getS2KUsage(), SecretKeyPacket.USAGE_AEAD);
    }

    private void testChangingCFBPassphrase(OpenPGPApi api)
            throws PGPException, IOException
    {
        OpenPGPKey key = api.readKeyOrCertificate().parseKey(OpenPGPTestKeys.ALICE_KEY);

        OpenPGPKey.OpenPGPSecretKey secretKey = key.getPrimarySecretKey();
        isFalse("Expect Alice' key to not be locked initially", secretKey.isLocked());

        OpenPGPKey.OpenPGPPrivateKey privateKey = secretKey.unlock();
        OpenPGPKey.OpenPGPSecretKey locked = privateKey.changePassphrase(
                "sw0rdf1sh".toCharArray(), api.getImplementation(), false);
        isTrue("Expect Alice' key to be locked after locking", locked.isLocked());
        isEquals("Expect CFB mode to be used for locking, since we did not use AEAD.",
                locked.getPGPSecretKey().getS2KUsage(), SecretKeyPacket.USAGE_SHA1);
        isTrue("Expect key to be unlockable with used passphrase",
                locked.isPassphraseCorrect("sw0rdf1sh".toCharArray()));

        privateKey = locked.unlock("sw0rdf1sh".toCharArray());
        OpenPGPKey.OpenPGPSecretKey relocked = privateKey.changePassphrase("0r4ng3".toCharArray());
        isEquals("Expect CFB to be used after changing passphrase of CFB-protected key",
                relocked.getPGPSecretKey().getS2KUsage(), SecretKeyPacket.USAGE_SHA1);
        isTrue("Expect key to be unlockable with new passphrase",
                relocked.isPassphraseCorrect("0r4ng3".toCharArray()));

        privateKey = relocked.unlock("0r4ng3".toCharArray());
        OpenPGPKey.OpenPGPSecretKey unlocked = privateKey.removePassphrase();
        isFalse("Expect key to be unlocked after removing passphrase", unlocked.isLocked());
    }

    @Override
    public String getName()
    {
        return "ChangeKeyPassphraseTest";
    }

    public static void main(String[] args)
    {
        runTest(new ChangeKeyPassphraseTest());
    }
}
