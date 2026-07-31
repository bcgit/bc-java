package org.bouncycastle.crypto.examples;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.engines.SM9Engine;
import org.bouncycastle.crypto.generators.SM9EncMasterKeyPairGenerator;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9EncMasterPublicKeyParameters;
import org.bouncycastle.crypto.params.SM9EncPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9EncPublicKeyParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * Example of the SM9 identity-based public key encryption algorithm (GM/T 0044.4-2016)
 * through the lightweight API: the sender encrypts to a recipient's identity, and the
 * recipient decrypts with the private key the KGC derived for that identity.
 * <p>
 * SM9 is identity-based: a trusted Key Generation Centre (KGC) holds the encryption
 * master key pair ({@link SM9EncMasterKeyPairGenerator}) and derives each user's
 * decryption key from the user's identity with {@code generateUserKey} under the
 * encryption hid (the key-extraction operation - deterministic, and inherently
 * escrowed: the KGC can derive every user's key). The sender needs no certificate: the
 * recipient key is formed from the published master public key and the recipient's
 * identity alone, via {@code getUserPublicKey}.
 * <p>
 * GM/T 0044.4 defines two data-encapsulation methods, both shown here: SM4 in ECB mode
 * with PKCS#7 padding ({@link SM9Engine.Mode#SM4}, the {@link SM9Engine} default) and a
 * KDF-based stream cipher ({@link SM9Engine.Mode#STREAM}). The engine emits the raw
 * C1 || C3 || C2 ciphertext; the JCA {@code Cipher.SM9} wraps the same values in the
 * self-describing GM/T 0080-2020 SM9Cipher structure instead.
 */
public class SM9EngineExample
{
    public static void main(String[] args)
        throws Exception
    {
        SecureRandom random = new SecureRandom();

        // 1. KGC: generate the SM9 encryption master key pair and derive Bob's
        //    decryption key from his identity under the encryption hid (0x03).
        SM9EncMasterKeyPairGenerator kpGen = new SM9EncMasterKeyPairGenerator();
        kpGen.init(new KeyGenerationParameters(random, 256));
        AsymmetricCipherKeyPair master = kpGen.generateKeyPair();
        SM9EncMasterPrivateKeyParameters masterPriv = (SM9EncMasterPrivateKeyParameters)master.getPrivate();
        SM9EncMasterPublicKeyParameters masterPub = (SM9EncMasterPublicKeyParameters)master.getPublic();

        byte[] bobIdentity = Strings.toByteArray("Bob");
        SM9EncPrivateKeyParameters bobKey =
            masterPriv.generateUserKey(bobIdentity, SM9EncMasterPrivateKeyParameters.HID);

        // 2. Sender: form Bob's public key from the published master public key and his
        //    identity - no certificate or KGC interaction needed - and encrypt (SM4
        //    data encapsulation, the default mode).
        SM9EncPublicKeyParameters bobPublic = masterPub.getUserPublicKey(bobIdentity);
        byte[] message = Strings.toByteArray("Chinese IBE standard");

        SM9Engine engine = new SM9Engine();
        engine.init(true, new ParametersWithRandom(bobPublic, random));
        byte[] ciphertext = engine.processBlock(message, 0, message.length);

        System.out.println("SM4-mode ciphertext (C1 || C3 || C2, " + ciphertext.length
            + " bytes): " + Hex.toHexString(ciphertext));

        // 3. Bob: decrypt with his identity key.
        engine.init(false, bobKey);
        byte[] decrypted = engine.processBlock(ciphertext, 0, ciphertext.length);

        if (!Arrays.areEqual(message, decrypted))
        {
            throw new IllegalStateException("SM9 decryption did not recover the message");
        }

        // 4. The same exchange with the KDF stream-cipher data encapsulation.
        SM9Engine streamEngine = new SM9Engine(SM9Engine.Mode.STREAM);
        streamEngine.init(true, new ParametersWithRandom(bobPublic, random));
        byte[] streamCiphertext = streamEngine.processBlock(message, 0, message.length);

        streamEngine.init(false, bobKey);
        if (!Arrays.areEqual(message, streamEngine.processBlock(streamCiphertext, 0, streamCiphertext.length)))
        {
            throw new IllegalStateException("SM9 stream-mode decryption did not recover the message");
        }

        System.out.println("message encrypted to \"Bob\" and recovered in both GM/T 0044.4 modes.");
    }
}
