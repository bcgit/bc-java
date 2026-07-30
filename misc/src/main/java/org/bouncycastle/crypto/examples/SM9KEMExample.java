package org.bouncycastle.crypto.examples;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.generators.SM9EncMasterKeyPairGenerator;
import org.bouncycastle.crypto.kems.SM9KEMExtractor;
import org.bouncycastle.crypto.kems.SM9KEMGenerator;
import org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9EncMasterPublicKeyParameters;
import org.bouncycastle.crypto.params.SM9EncPrivateKeyParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * Example of the SM9 identity-based key encapsulation mechanism (GM/T 0044.4-2016)
 * through the lightweight API: the sender encapsulates a fresh shared key to a
 * recipient's identity, and the recipient recovers it from the encapsulation with the
 * private key the KGC derived for that identity.
 * <p>
 * SM9 is identity-based: a trusted Key Generation Centre (KGC) holds the encryption
 * master key pair ({@link SM9EncMasterKeyPairGenerator}) and derives each user's
 * decapsulation key from the user's identity with {@code generateUserKey} under the
 * encryption hid (the key-extraction operation - deterministic, and inherently
 * escrowed: the KGC can derive every user's key). The sender needs no certificate: the
 * recipient key is formed from the published master public key and the recipient's
 * identity alone, via {@code getUserPublicKey}. The shared secret is the GM/T 0044.4
 * KDF output at the requested size; the encapsulation C is a G1 point (x || y,
 * 64 bytes).
 */
public class SM9KEMExample
{
    public static void main(String[] args)
        throws Exception
    {
        SecureRandom random = new SecureRandom();

        // 1. KGC: generate the SM9 encryption master key pair and derive Bob's
        //    decapsulation key from his identity under the encryption hid (0x03).
        SM9EncMasterKeyPairGenerator kpGen = new SM9EncMasterKeyPairGenerator();
        kpGen.init(new KeyGenerationParameters(random, 256));
        AsymmetricCipherKeyPair master = kpGen.generateKeyPair();
        SM9EncMasterPrivateKeyParameters masterPriv = (SM9EncMasterPrivateKeyParameters)master.getPrivate();
        SM9EncMasterPublicKeyParameters masterPub = (SM9EncMasterPublicKeyParameters)master.getPublic();

        byte[] bobIdentity = Strings.toByteArray("Bob");
        SM9EncPrivateKeyParameters bobKey =
            masterPriv.generateUserKey(bobIdentity, SM9EncMasterPrivateKeyParameters.HID);

        // 2. Sender: encapsulate a fresh 128-bit key to Bob's identity, using only the
        //    published master public key - no certificate or KGC interaction needed.
        SM9KEMGenerator kemGen = new SM9KEMGenerator(128, random);
        SecretWithEncapsulation enc =
            kemGen.generateEncapsulated(masterPub.getUserPublicKey(bobIdentity));

        System.out.println("encapsulation C (" + enc.getEncapsulation().length + " bytes): "
            + Hex.toHexString(enc.getEncapsulation()));

        // 3. Bob: recover the shared key from the encapsulation with his identity key.
        SM9KEMExtractor extractor = new SM9KEMExtractor(bobKey, 128);
        byte[] recovered = extractor.extractSecret(enc.getEncapsulation());

        if (!Arrays.constantTimeAreEqual(enc.getSecret(), recovered))
        {
            throw new IllegalStateException("SM9 KEM decapsulation did not recover the key");
        }

        System.out.println("shared 128-bit key encapsulated to \"Bob\" and recovered: "
            + Hex.toHexString(recovered));
    }
}
