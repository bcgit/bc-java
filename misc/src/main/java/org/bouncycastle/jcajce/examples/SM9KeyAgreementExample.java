package org.bouncycastle.jcajce.examples;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.KeyAgreement;

import org.bouncycastle.jcajce.interfaces.SM9EncMasterPrivateKey;
import org.bouncycastle.jcajce.interfaces.SM9EncMasterPublicKey;
import org.bouncycastle.jcajce.spec.SM9KeyExchangeSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * Example of the SM9 identity-based key exchange (GM/T 0044.3-2016) through the
 * BouncyCastle provider's {@code KeyAgreement.SM9}: two parties, knowing only each
 * other's identities and the published encryption master public key, agree a shared
 * key - no certificates are involved.
 * <p>
 * SM9 is identity-based: a trusted Key Generation Centre (KGC) holds the encryption
 * master key pair (from {@code KeyPairGenerator.SM9-ENC}) and derives each party's
 * key-exchange key pair from its identity via
 * {@link SM9EncMasterPrivateKey#generateExchangeKeyPair(byte[])} (the KGC
 * key-extraction operation; exchange keys and KEM/decryption keys are distinct
 * objects, and the agreement rejects the latter). The model carries inherent key
 * escrow - the KGC can derive every user's key.
 * <p>
 * The exchange is two-round, so it uses the {@code KeyAgreement} API's two-phase
 * form. Each party initialises with its own key-exchange private key and an
 * {@link SM9KeyExchangeSpec} carrying just the role and the agreed key length;
 * the first {@code doPhase} names the peer - through its identity-derived public
 * key from {@link SM9EncMasterPublicKey#getUserPublicKey(byte[], byte)} - and
 * returns that party's own ephemeral value R to send; the last {@code doPhase}
 * consumes the peer's R. The ephemeral is generated inside the provider under the
 * master public key carried on the party's own user key, so no key-pair
 * generation step is needed and the ephemeral cannot be mis-bound to a different
 * master key. A user therefore never handles master-level private material: only
 * its own key, from the KGC, and the published master public key.
 * <p>
 * The optional GM/T 0044.3 key-confirmation tags S_A / S_B have no channel in the
 * {@code KeyAgreement} API - a caller wanting them should use the lightweight
 * {@code org.bouncycastle.crypto.agreement.SM9KeyExchange} directly (see
 * {@code org.bouncycastle.crypto.examples.SM9KeyExchangeExample}).
 */
public class SM9KeyAgreementExample
{
    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());
        SecureRandom random = new SecureRandom();

        // 1. KGC: generate the SM9 encryption master key pair and derive each party's
        //    key-exchange key pair from its identity.
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("SM9-ENC", "BC");
        kpGen.initialize(256, random);
        KeyPair master = kpGen.generateKeyPair();
        SM9EncMasterPrivateKey masterPriv = (SM9EncMasterPrivateKey)master.getPrivate();

        byte[] aliceIdentity = Strings.toByteArray("Alice");
        byte[] bobIdentity = Strings.toByteArray("Bob");
        KeyPair alice = masterPriv.generateExchangeKeyPair(aliceIdentity);
        KeyPair bob = masterPriv.generateExchangeKeyPair(bobIdentity);

        // 2. Each party: initialise with its own key and the role, then name the peer -
        //    the first doPhase hands back this party's ephemeral value R to send.
        //    Only the published master public key is needed to name a peer.
        SM9EncMasterPublicKey masterPub = (SM9EncMasterPublicKey)master.getPublic();
        byte hid = SM9EncMasterPublicKey.HID_EXCHANGE;

        KeyAgreement aliceAgreement = KeyAgreement.getInstance("SM9", "BC");
        aliceAgreement.init(alice.getPrivate(), new SM9KeyExchangeSpec(true), random);
        Key ra = aliceAgreement.doPhase(masterPub.getUserPublicKey(bobIdentity, hid), false);

        KeyAgreement bobAgreement = KeyAgreement.getInstance("SM9", "BC");
        bobAgreement.init(bob.getPrivate(), new SM9KeyExchangeSpec(false), random);
        Key rb = bobAgreement.doPhase(masterPub.getUserPublicKey(aliceIdentity, hid), false);

        // ... which travels as the standard's 64-byte x || y form
        byte[] raWire = ra.getEncoded();
        byte[] rbWire = rb.getEncoded();

        // 3. Each party: consume the peer's R and derive the shared key.
        aliceAgreement.doPhase(masterPub.getExchangeEphemeral(rbWire), true);
        byte[] aliceShared = aliceAgreement.generateSecret();

        bobAgreement.doPhase(masterPub.getExchangeEphemeral(raWire), true);
        byte[] bobShared = bobAgreement.generateSecret();

        System.out.println("initiator shared key: " + Hex.toHexString(aliceShared));
        System.out.println("responder shared key: " + Hex.toHexString(bobShared));

        // shared keys are secrets - compare in constant time
        if (!Arrays.constantTimeAreEqual(aliceShared, bobShared))
        {
            throw new IllegalStateException("SM9 key agreement did not agree");
        }

        System.out.println("shared 128-bit key agreed between \"Alice\" and \"Bob\" through KeyAgreement.SM9.");
    }
}
