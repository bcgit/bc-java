package org.bouncycastle.jcajce.examples;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.HybridValueParameterSpec;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * Example of the SP 800-56C Rev. 2 generic composite key establishment (NIST IR 8547, Section
 * 3.2.1) through the JCE: an ML-KEM-768 encapsulation and an ECDH P-256 key agreement are combined
 * by feeding the KDF Z' = Z || T (or T || Z), where Z is the ECDH shared secret and T is the
 * ML-KEM shared secret.
 * <p>
 * The ML-KEM secret is T rather than Z because T may come from any source, whereas Z has to come
 * from an approved scheme; ECDH is quantum vulnerable and ML-KEM is the part NIST wants added, so
 * either assignment is a legitimate composite - the example follows the one that keeps the
 * existing ECDH agreement as the "main" scheme. The derived key is secure as long as either
 * component is.
 * <p>
 * {@link HybridValueParameterSpec} appends T by default and prepends it when asked. The two orders
 * derive different keys, and NIST IR 8547 says the order must be fixed at the protocol level, so
 * both parties have to agree on one in advance - this example derives under both to show that
 * they differ, and uses Z || T for the final key.
 */
public class HybridMLKEMECDHExample
{
    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        // 1. The recipient has an ML-KEM-768 key pair; both parties have ECDH P-256 key pairs.
        KeyPair mlkemRecipient = KeyPairGenerator.getInstance("ML-KEM-768", "BC").generateKeyPair();

        KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC", "BC");
        ecGen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair ecAlice = ecGen.generateKeyPair();
        KeyPair ecBob = ecGen.generateKeyPair();

        // 2. Alice (sender) encapsulates to Bob's ML-KEM key. T is the encapsulated secret.
        KeyGenerator encapsulator = KeyGenerator.getInstance("ML-KEM-768", "BC");
        encapsulator.init(new KEMGenerateSpec.Builder(mlkemRecipient.getPublic(), "Secret", 256).withNoKdf().build());
        SecretKeyWithEncapsulation aliceKem = (SecretKeyWithEncapsulation)encapsulator.generateKey();

        // 3. Bob decapsulates to get the same T.
        KeyGenerator decapsulator = KeyGenerator.getInstance("ML-KEM-768", "BC");
        decapsulator.init(new KEMExtractSpec.Builder(mlkemRecipient.getPrivate(), aliceKem.getEncapsulation(), "Secret", 256).withNoKdf().build());
        SecretKeyWithEncapsulation bobKem = (SecretKeyWithEncapsulation)decapsulator.generateKey();

        // Protocol-agreed context, passed to the KDF as the "otherInfo" (SP 800-56C OtherInfo).
        byte[] ukm = Strings.toByteArray("HybridMLKEMECDHExample v1");

        // 4. Each side runs the ECDH agreement with T mixed in. The spec zeroises T on destroy(),
        //    so each side is given its own copy of the secret.
        SecretKey aliceAppend = derive(ecAlice, ecBob, aliceKem.getEncoded(), false, ukm);
        SecretKey bobAppend = derive(ecBob, ecAlice, bobKem.getEncoded(), false, ukm);

        SecretKey alicePrepend = derive(ecAlice, ecBob, aliceKem.getEncoded(), true, ukm);
        SecretKey bobPrepend = derive(ecBob, ecAlice, bobKem.getEncoded(), true, ukm);

        System.out.println("Z || T (Alice)   : " + Hex.toHexString(aliceAppend.getEncoded()));
        System.out.println("Z || T (Bob)     : " + Hex.toHexString(bobAppend.getEncoded()));
        System.out.println("T || Z (Alice)   : " + Hex.toHexString(alicePrepend.getEncoded()));
        System.out.println("T || Z (Bob)     : " + Hex.toHexString(bobPrepend.getEncoded()));

        if (!Arrays.constantTimeAreEqual(aliceAppend.getEncoded(), bobAppend.getEncoded())
            || !Arrays.constantTimeAreEqual(alicePrepend.getEncoded(), bobPrepend.getEncoded()))
        {
            throw new IllegalStateException("hybrid keys do not match");
        }

        // the order is part of the protocol: a party using the other order gets a different key.
        if (Arrays.areEqual(aliceAppend.getEncoded(), alicePrepend.getEncoded()))
        {
            throw new IllegalStateException("Z || T and T || Z gave the same key");
        }

        System.out.println("hybrid ML-KEM-768 + ECDH P-256 keys match for both orders; the orders differ from each other.");
    }

    private static SecretKey derive(KeyPair own, KeyPair peer, byte[] t, boolean prependT, byte[] ukm)
        throws Exception
    {
        HybridValueParameterSpec spec = new HybridValueParameterSpec(t, prependT, new UserKeyingMaterialSpec(ukm));

        KeyAgreement agreement = KeyAgreement.getInstance("ECDHwithSHA256KDF", "BC");

        agreement.init(own.getPrivate(), spec);
        agreement.doPhase(peer.getPublic(), true);

        SecretKey key = agreement.generateSecret("AES[256]");

        spec.destroy();

        return key;
    }
}
