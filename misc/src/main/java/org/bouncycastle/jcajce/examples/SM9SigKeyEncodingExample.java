package org.bouncycastle.jcajce.examples;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.jcajce.interfaces.SM9SigMasterPrivateKey;
import org.bouncycastle.jcajce.interfaces.SM9SigMasterPublicKey;
import org.bouncycastle.jcajce.interfaces.SM9SigUserPrivateKey;
import org.bouncycastle.jcajce.interfaces.SM9SigUserPublicKey;
import org.bouncycastle.jcajce.spec.SM9SigUserPrivateKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * Example of generating, encoding and regenerating SM9 (GM/T 0044.2-2016) signature keys
 * through the BouncyCastle provider's JCA layer - a complement to {@link SM9SigExample},
 * which covers the sign/verify workflow itself.
 * <p>
 * A user's signature private key does not carry the signature master public key or the
 * identity it was derived under, so its bare PKCS#8 encoding does not determine a usable
 * key. This example plays out a realistic split: a KGC that holds the master private key
 * and extracts user keys, and a signing service that holds only a stored user key plus the
 * KGC's published master public key - it never sees the master private key at all - and
 * can still sign, by rebuilding the private key through {@link SM9SigUserPrivateKeySpec}.
 * The master key pair, in contrast, is self-sufficient and round-trips through the plain
 * X.509 / PKCS#8 specs.
 */
public class SM9SigKeyEncodingExample
{
    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());
        SecureRandom random = new SecureRandom();

        // 1. KGC: generate the SM9 signature master key pair and derive Alice's user key
        //    pair from her identity.
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("SM9-SIGN", "BC");
        kpGen.initialize(256, random);
        KeyPair master = kpGen.generateKeyPair();

        byte[] aliceIdentity = Strings.toByteArray("Alice");
        KeyPair alice = ((SM9SigMasterPrivateKey)master.getPrivate()).generateUserKeyPair(aliceIdentity);

        // 2. KGC: encode everything that will be handed to the signing service - the
        //    published master public key (X.509) and Alice's user private key (PKCS#8).
        //    The master private key never leaves the KGC.
        byte[] masterPublicEncoded = master.getPublic().getEncoded();
        byte[] aliceEncoded = alice.getPrivate().getEncoded();

        System.out.println("master public key  (X.509, " + masterPublicEncoded.length + " bytes): "
            + Hex.toHexString(masterPublicEncoded));
        System.out.println("Alice's private key (PKCS#8, " + aliceEncoded.length + " bytes): "
            + Hex.toHexString(aliceEncoded));

        // 3. Signing service: starting from nothing but those bytes plus the identity they
        //    were told the key belongs to, rebuild both keys through KeyFactory.SM9. The
        //    master public key rebuilds from the plain X.509 spec; Alice's private key
        //    needs the extra context an SM9SigUserPrivateKeySpec supplies, since the
        //    encoding alone is not enough.
        KeyFactory kf = KeyFactory.getInstance("SM9", "BC");
        SM9SigMasterPublicKey masterPublic = (SM9SigMasterPublicKey)kf.generatePublic(
            new X509EncodedKeySpec(masterPublicEncoded));
        PrivateKey aliceRebuilt = kf.generatePrivate(
            new SM9SigUserPrivateKeySpec(aliceEncoded, masterPublic, aliceIdentity));

        // 4. The rebuilt key knows its own identity - the signing service does not need to
        //    track it alongside the key.
        System.out.println("rebuilt key identity: " + Strings.fromByteArray(
            ((SM9SigUserPrivateKey)aliceRebuilt).getIdentity()));

        // 5. Signing service: sign with the rebuilt key.
        byte[] message = Strings.toByteArray("Chinese IBS standard");
        Signature signer = Signature.getInstance("SM9", "BC");
        signer.initSign(aliceRebuilt);
        signer.update(message);
        byte[] signature = signer.sign();

        // 6. Verifier: independently derive Alice's public key from the master public key
        //    and her identity, and confirm it also carries that context directly.
        PublicKey alicePublic = masterPublic.getUserPublicKey(aliceIdentity);
        SM9SigUserPublicKey aliceUserPublic = (SM9SigUserPublicKey)alicePublic;
        System.out.println("verifier-derived public key identity:   " + Strings.fromByteArray(aliceUserPublic.getIdentity()));
        System.out.println("verifier-derived public key master key: "
            + Hex.toHexString(aliceUserPublic.getMasterPublicKey().getEncoded()));

        Signature verifier = Signature.getInstance("SM9", "BC");
        verifier.initVerify(alicePublic);
        verifier.update(message);
        if (!verifier.verify(signature))
        {
            throw new IllegalStateException("SM9 signature (from a rebuilt key) failed to verify");
        }
        System.out.println("signature from the rebuilt key verified.");

        // 7. KeyFactory.getKeySpec runs the same extraction the other way: given a live key
        //    object, hand back the spec that would rebuild it - so a caller who already has
        //    the key in hand can persist it without separately tracking the master public
        //    key or the identity either.
        SM9SigUserPrivateKeySpec extracted = kf.getKeySpec(alice.getPrivate(), SM9SigUserPrivateKeySpec.class);
        if (!Arrays.areEqual(extracted.getEncoded(), aliceEncoded)
            || !Arrays.areEqual(extracted.getIdentity(), aliceIdentity)
            || !Arrays.areEqual(extracted.getMasterPublicKey().getEncoded(), masterPublicEncoded))
        {
            throw new IllegalStateException("SM9SigUserPrivateKeySpec extraction mismatch");
        }
        System.out.println("getKeySpec extracted the same encoding, identity and master public key.");

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
