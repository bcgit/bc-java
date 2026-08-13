package org.bouncycastle.jcajce.examples;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.bouncycastle.jcajce.interfaces.SM9EncMasterPrivateKey;
import org.bouncycastle.jcajce.interfaces.SM9EncMasterPublicKey;
import org.bouncycastle.jcajce.interfaces.SM9EncUserPrivateKey;
import org.bouncycastle.jcajce.interfaces.SM9EncUserPublicKey;
import org.bouncycastle.jcajce.spec.SM9EncUserPrivateKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * Example of generating, encoding and regenerating SM9 (GM/T 0044.4-2016) encryption keys
 * through the BouncyCastle provider's JCA layer - a complement to {@link SM9CipherExample},
 * which covers the encrypt/decrypt workflow itself.
 * <p>
 * A user's encryption (decryption) private key does not carry the encryption master public
 * key, the identity or the hid it was derived under, so its bare PKCS#8 encoding does not
 * determine a usable key. This example plays out a realistic split: a KGC that holds the
 * master private key and extracts user keys, and a decryption service that holds only a
 * stored user key plus the KGC's published master public key, the recipient's identity and
 * the hid - it never sees the master private key at all - and can still decrypt, by
 * rebuilding the private key through {@link SM9EncUserPrivateKeySpec}. The master key pair,
 * in contrast, is self-sufficient and round-trips through the plain X.509 / PKCS#8 specs.
 */
public class SM9EncKeyEncodingExample
{
    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());
        SecureRandom random = new SecureRandom();

        // 1. KGC: generate the SM9 encryption master key pair and derive Bob's user key
        //    pair from his identity, under the KEM/decryption hid.
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("SM9-ENC", "BC");
        kpGen.initialize(256, random);
        KeyPair master = kpGen.generateKeyPair();

        byte[] bobIdentity = Strings.toByteArray("Bob");
        byte hid = SM9EncMasterPublicKey.HID;
        KeyPair bob = ((SM9EncMasterPrivateKey)master.getPrivate()).generateUserKeyPair(bobIdentity, hid);

        // 2. KGC: encode everything that will be handed to the decryption service - the
        //    published master public key (X.509) and Bob's user private key (PKCS#8). The
        //    master private key never leaves the KGC.
        byte[] masterPublicEncoded = master.getPublic().getEncoded();
        byte[] bobEncoded = bob.getPrivate().getEncoded();

        System.out.println("master public key (X.509, " + masterPublicEncoded.length + " bytes): "
            + Hex.toHexString(masterPublicEncoded));
        System.out.println("Bob's private key  (PKCS#8, " + bobEncoded.length + " bytes): "
            + Hex.toHexString(bobEncoded));

        // 3. Decryption service: starting from nothing but those bytes plus the identity
        //    and hid it was told the key belongs to, rebuild both keys through
        //    KeyFactory.SM9. The master public key rebuilds from the plain X.509 spec;
        //    Bob's private key needs the extra context an SM9EncUserPrivateKeySpec
        //    supplies, since the encoding alone is not enough.
        KeyFactory kf = KeyFactory.getInstance("SM9", "BC");
        SM9EncMasterPublicKey masterPublic = (SM9EncMasterPublicKey)kf.generatePublic(
            new X509EncodedKeySpec(masterPublicEncoded));
        PrivateKey bobRebuilt = kf.generatePrivate(
            new SM9EncUserPrivateKeySpec(bobEncoded, masterPublic, bobIdentity, hid));

        // 4. The rebuilt key knows its own identity - the decryption service does not need
        //    to track it alongside the key.
        System.out.println("rebuilt key identity: " + Strings.fromByteArray(
            ((SM9EncUserPrivateKey)bobRebuilt).getIdentity()));

        // 5. Sender: independently derive Bob's public key from the master public key and
        //    his identity, and confirm it also carries that context directly; encrypt to it.
        PublicKey bobPublic = masterPublic.getUserPublicKey(bobIdentity);
        SM9EncUserPublicKey bobUserPublic = (SM9EncUserPublicKey)bobPublic;
        System.out.println("sender-derived public key identity:   " + Strings.fromByteArray(bobUserPublic.getIdentity()));
        System.out.println("sender-derived public key master key: "
            + Hex.toHexString(bobUserPublic.getMasterPublicKey().getEncoded()));

        byte[] message = Strings.toByteArray("Chinese IBE standard");
        Cipher encrypt = Cipher.getInstance("SM9", "BC");
        encrypt.init(Cipher.ENCRYPT_MODE, bobPublic, random);
        byte[] ciphertext = encrypt.doFinal(message);

        // 6. Decryption service: decrypt with the rebuilt key.
        Cipher decrypt = Cipher.getInstance("SM9", "BC");
        decrypt.init(Cipher.DECRYPT_MODE, bobRebuilt);
        byte[] recovered = decrypt.doFinal(ciphertext);

        if (!Arrays.areEqual(message, recovered))
        {
            throw new IllegalStateException("SM9 decryption (with a rebuilt key) did not recover the message");
        }
        System.out.println("decrypted with the rebuilt key: " + Strings.fromByteArray(recovered));

        // 7. KeyFactory.getKeySpec runs the same extraction the other way: given a live key
        //    object, hand back the spec that would rebuild it - including the hid, which
        //    the key does not otherwise expose directly - so a caller who already has the
        //    key in hand can persist it without separately tracking that context.
        SM9EncUserPrivateKeySpec extracted = kf.getKeySpec(bob.getPrivate(), SM9EncUserPrivateKeySpec.class);
        if (!Arrays.areEqual(extracted.getEncoded(), bobEncoded)
            || !Arrays.areEqual(extracted.getIdentity(), bobIdentity)
            || extracted.getHid() != hid
            || !Arrays.areEqual(extracted.getMasterPublicKey().getEncoded(), masterPublicEncoded))
        {
            throw new IllegalStateException("SM9EncUserPrivateKeySpec extraction mismatch");
        }
        System.out.println("getKeySpec extracted the same encoding, identity, hid and master public key.");

        // 8. The master key pair, unlike the user keys, is self-sufficient and round-trips
        //    through the plain PKCS#8 spec too.
        PrivateKey masterPrivateRebuilt = kf.generatePrivate(
            new PKCS8EncodedKeySpec(master.getPrivate().getEncoded()));
        if (!Arrays.areEqual(masterPrivateRebuilt.getEncoded(), master.getPrivate().getEncoded()))
        {
            throw new IllegalStateException("SM9 master private key encoding round-trip mismatch");
        }
        System.out.println("master private key round-trips through plain PKCS#8 (KGC side only).");
    }
}
