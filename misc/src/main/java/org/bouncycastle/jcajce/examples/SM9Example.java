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

import javax.crypto.KeyGenerator;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.interfaces.SM9EncMasterPrivateKey;
import org.bouncycastle.jcajce.interfaces.SM9EncMasterPublicKey;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * Example of the SM9 identity-based key encapsulation mechanism (GM/T 0044.4-2016) through the
 * BouncyCastle provider's {@code KeyGenerator.SM9-KEM}: the sender encapsulates a fresh AES key to a
 * recipient's identity, and the recipient recovers it from the encapsulation with its private key.
 * <p>
 * SM9 is identity-based: a trusted Key Generation Centre (KGC) holds a master key pair and derives
 * each user's key pair from the user's identity - so there are no certificates, and a sender needs
 * only the published master public key plus the recipient's identity. The master key pair comes from
 * {@code KeyPairGenerator.SM9-ENC}; a user's key pair is then derived from the master private key via
 * {@link SM9EncMasterPrivateKey#generateUserKeyPair(byte[])} - a deterministic, KGC-side derivation -
 * while a sender forms the recipient's public key from the master public key alone via
 * {@link SM9EncMasterPublicKey#getUserPublicKey(byte[])}. The model carries inherent key escrow
 * (the KGC can derive every user's key), so the KGC must be trusted accordingly.
 * <p>
 * The requested key length (the {@link KEMGenerateSpec}'s key size) is produced directly by SM9's own
 * GM/T 0044.4 KDF; the spec's generic KDF fields are not applied, as an external KDF on top would break
 * interoperability with other GM/T 0044.4 implementations.
 */
public class SM9Example
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

        // 2. KGC: generate Bob's key pair from his identity - derived from the master
        //    private key (deterministic).
        byte[] bobId = Strings.toByteArray("Bob");
        KeyPair bob = ((SM9EncMasterPrivateKey)master.getPrivate()).generateUserKeyPair(bobId);

        // 3. Sender: derive Bob's public key from the published master public key and
        //    his identity - no certificate or KGC interaction needed - and encapsulate
        //    a 128-bit AES key to it.
        PublicKey bobPublic = ((SM9EncMasterPublicKey)master.getPublic()).getUserPublicKey(bobId);
        KeyGenerator encapsulator = KeyGenerator.getInstance("SM9-KEM", "BC");
        encapsulator.init(new KEMGenerateSpec(bobPublic, "AES", 128), random);
        SecretKeyWithEncapsulation encapsulated = (SecretKeyWithEncapsulation)encapsulator.generateKey();

        byte[] sharedSecret = encapsulated.getEncoded();
        byte[] encapsulation = encapsulated.getEncapsulation();

        // 4. Bob: decapsulate with his private key and the received encapsulation.
        KeyGenerator decapsulator = KeyGenerator.getInstance("SM9-KEM", "BC");
        decapsulator.init(new KEMExtractSpec(bob.getPrivate(), encapsulation, "AES", 128));
        SecretKeyWithEncapsulation decapsulated = (SecretKeyWithEncapsulation)decapsulator.generateKey();

        byte[] recoveredSecret = decapsulated.getEncoded();

        System.out.println("SM9-KEM encapsulation (" + encapsulation.length + " bytes): " + Hex.toHexString(encapsulation));
        System.out.println("sender    shared secret: " + Hex.toHexString(sharedSecret));
        System.out.println("recipient shared secret: " + Hex.toHexString(recoveredSecret));

        if (!Arrays.constantTimeAreEqual(sharedSecret, recoveredSecret))
        {
            throw new IllegalStateException("SM9 KEM decapsulation did not recover the shared key");
        }

        System.out.println("shared " + (sharedSecret.length * 8) + "-bit AES key established with \"Bob\".");

        // 5. The master keys round-trip through their JCA X.509 / PKCS#8 encodings.
        KeyFactory kf = KeyFactory.getInstance("SM9", "BC");
        PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(master.getPublic().getEncoded()));
        PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(master.getPrivate().getEncoded()));
        if (!Arrays.areEqual(pub.getEncoded(), master.getPublic().getEncoded())
            || !Arrays.areEqual(priv.getEncoded(), master.getPrivate().getEncoded()))
        {
            throw new IllegalStateException("SM9 master key encoding round-trip mismatch");
        }

        System.out.println("master keys round-trip through X.509 / PKCS#8.");
    }
}
