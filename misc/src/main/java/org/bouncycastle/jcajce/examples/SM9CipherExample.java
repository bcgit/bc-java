package org.bouncycastle.jcajce.examples;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;

import org.bouncycastle.jcajce.interfaces.SM9EncMasterPrivateKey;
import org.bouncycastle.jcajce.interfaces.SM9EncMasterPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * Example of SM9 identity-based public-key encryption (GM/T 0044.4-2016) through the
 * BouncyCastle provider's {@code Cipher.SM9}: a sender encrypts to a recipient's public
 * key, and the recipient decrypts with the private key its identity was derived to.
 * <p>
 * SM9 is identity-based: a trusted Key Generation Centre (KGC) holds an encryption master
 * key pair and derives each user's key pair from the user's identity - so there are no
 * certificates, and a sender forms the recipient's public key from the published master
 * public key and the recipient's identity alone, via
 * {@link SM9EncMasterPublicKey#getUserPublicKey(byte[])} - the same recipient key the
 * SM9-KEM encapsulates to. The master key pair comes from {@code KeyPairGenerator.SM9-ENC};
 * a user's key pair is derived from the master private key via
 * {@link SM9EncMasterPrivateKey#generateUserKeyPair(byte[], byte)} (the KGC key-extraction
 * operation). The model carries inherent key escrow (the KGC can derive every user's key),
 * so the KGC must be trusted accordingly.
 * <p>
 * GM/T 0044.4 defines two data-encapsulation modes: the default wraps the message with the
 * SM4 block cipher ({@code Cipher.SM9}); {@code SM9/XOR/NoPadding} uses the KDF as a stream
 * cipher. The ciphertext (GM/T 0080-2020 SM9Cipher: enType, C1, C3, C2) is self-describing,
 * so a single {@code Cipher.SM9} decrypts either mode.
 */
public class SM9CipherExample
{
    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());
        SecureRandom random = new SecureRandom();

        // 1. KGC: generate the SM9 encryption master key pair.
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("SM9-ENC", "BC");
        kpGen.initialize(256, random);
        KeyPair master = kpGen.generateKeyPair();

        // 2. KGC: derive Bob's key pair from his identity (deterministic); Bob decrypts with
        //    the private half.
        byte[] bobIdentity = Strings.toByteArray("Bob");
        KeyPair bob = ((SM9EncMasterPrivateKey)master.getPrivate()).generateUserKeyPair(bobIdentity,
            SM9EncMasterPublicKey.HID);

        byte[] message = Strings.toByteArray("Chinese IBE standard");

        // 3. Sender: form Bob's public key from the published master public key and his
        //    identity - no certificate or KGC interaction needed - and encrypt to it
        //    (default SM4 mode).
        PublicKey bobPublic = ((SM9EncMasterPublicKey)master.getPublic()).getUserPublicKey(bobIdentity);
        Cipher encrypt = Cipher.getInstance("SM9", "BC");
        encrypt.init(Cipher.ENCRYPT_MODE, bobPublic, random);
        byte[] ciphertext = encrypt.doFinal(message);

        // 4. Bob: decrypt with his derived private key.
        Cipher decrypt = Cipher.getInstance("SM9", "BC");
        decrypt.init(Cipher.DECRYPT_MODE, bob.getPrivate());
        byte[] recovered = decrypt.doFinal(ciphertext);

        if (!Arrays.areEqual(message, recovered))
        {
            throw new IllegalStateException("SM9 decryption did not recover the message");
        }

        System.out.println("Cipher.SM9 (SM4 mode) ciphertext (" + ciphertext.length + " bytes): "
            + Hex.toHexString(ciphertext));
        System.out.println("decrypted for \"Bob\" back to: " + Strings.fromByteArray(recovered));

        // 5. The KDF stream mode is selected on encryption; the same Cipher.SM9 decrypts it,
        //    since the ciphertext carries its own mode.
        Cipher streamEncrypt = Cipher.getInstance("SM9/XOR/NoPadding", "BC");
        streamEncrypt.init(Cipher.ENCRYPT_MODE, bobPublic, random);
        byte[] streamCiphertext = streamEncrypt.doFinal(message);

        Cipher streamDecrypt = Cipher.getInstance("SM9", "BC");
        streamDecrypt.init(Cipher.DECRYPT_MODE, bob.getPrivate());
        if (!Arrays.areEqual(message, streamDecrypt.doFinal(streamCiphertext)))
        {
            throw new IllegalStateException("SM9 stream-mode decryption did not recover the message");
        }

        System.out.println("Cipher.SM9 (stream mode) ciphertext (" + streamCiphertext.length + " bytes): "
            + Hex.toHexString(streamCiphertext));
        System.out.println("both data-encapsulation modes round-trip for \"Bob\".");
    }
}
