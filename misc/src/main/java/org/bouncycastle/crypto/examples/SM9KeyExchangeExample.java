package org.bouncycastle.crypto.examples;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.agreement.SM9KeyExchange;
import org.bouncycastle.crypto.generators.SM9EncMasterKeyPairGenerator;
import org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9EncPrivateKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * Example of the SM9 identity-based key exchange protocol (GM/T 0044.3-2016) through the
 * lightweight API: two parties, knowing only each other's identities and the published
 * encryption master public key, agree a shared key and confirm it. The protocol is not
 * exposed through the JCA provider - it is a stateful two-party exchange with roles and
 * key confirmation, which the lightweight {@link SM9KeyExchange} models directly.
 * <p>
 * SM9 is identity-based: a trusted Key Generation Centre (KGC) holds the encryption
 * master key pair (the key exchange reuses it with hid = 0x02) and derives each party's
 * exchange key from its identity. Each party constructs an {@link SM9KeyExchange} with
 * its own key, the peer's identity and its role, generates an ephemeral value R, and -
 * after swapping R values - computes the shared key; the optional confirmation tags
 * S_B / S_A prove to each side that the other derived the same key. Received tags must be
 * compared with {@link Arrays#constantTimeAreEqual(byte[], byte[])}.
 */
public class SM9KeyExchangeExample
{
    public static void main(String[] args)
        throws Exception
    {
        SecureRandom random = new SecureRandom();

        // 1. KGC: generate the SM9 encryption master key pair and derive each party's
        //    key-exchange private key (hid = 0x02) from its identity.
        SM9EncMasterKeyPairGenerator kpGen = new SM9EncMasterKeyPairGenerator();
        kpGen.init(new KeyGenerationParameters(random, 256));
        AsymmetricCipherKeyPair master = kpGen.generateKeyPair();
        SM9EncMasterPrivateKeyParameters masterPriv = (SM9EncMasterPrivateKeyParameters)master.getPrivate();

        byte[] aliceId = Strings.toByteArray("Alice");
        byte[] bobId = Strings.toByteArray("Bob");
        byte hid = SM9EncMasterPrivateKeyParameters.HID_EXCHANGE;
        SM9EncPrivateKeyParameters aliceKey = masterPriv.generateUserKey(aliceId, hid);
        SM9EncPrivateKeyParameters bobKey = masterPriv.generateUserKey(bobId, hid);

        // 2. Each party: construct the exchange with its own key, the peer's identity
        //    and its role, and generate an ephemeral value.
        SM9KeyExchange alice = new SM9KeyExchange(aliceKey, bobId, true);     // initiator
        SM9KeyExchange bob = new SM9KeyExchange(bobKey, aliceId, false);      // responder
        ECPoint ra = alice.generateEphemeral(random);
        ECPoint rb = bob.generateEphemeral(random);

        // 3. Swap R values and compute the 128-bit shared key on each side.
        byte[] aliceShared = alice.calculateKey(128, rb);
        byte[] bobShared = bob.calculateKey(128, ra);

        System.out.println("initiator shared key: " + Hex.toHexString(aliceShared));
        System.out.println("responder shared key: " + Hex.toHexString(bobShared));

        if (!Arrays.constantTimeAreEqual(aliceShared, bobShared))
        {
            throw new IllegalStateException("SM9 key exchange did not agree");
        }

        // 4. Optional key confirmation: the responder sends S_B, the initiator checks
        //    it and answers with S_A. Received tags are secret authenticators - always
        //    compare with constantTimeAreEqual.
        byte[] sbFromBob = bob.getResponderConfirmation();
        if (!Arrays.constantTimeAreEqual(alice.getResponderConfirmation(), sbFromBob))
        {
            throw new IllegalStateException("responder confirmation failed");
        }
        byte[] saFromAlice = alice.getInitiatorConfirmation();
        if (!Arrays.constantTimeAreEqual(bob.getInitiatorConfirmation(), saFromAlice))
        {
            throw new IllegalStateException("initiator confirmation failed");
        }

        System.out.println("shared 128-bit key agreed and confirmed between \"Alice\" and \"Bob\".");
    }
}
