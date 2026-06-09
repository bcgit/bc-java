package org.bouncycastle.jcajce.examples;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

import javax.crypto.KeyGenerator;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * Example of using Composite ML-KEM (draft-ietf-lamps-pq-composite-kem) through the JCE: generate a
 * composite key pair, encapsulate a shared secret to the public key, and recover it with the
 * private key.
 * <p>
 * A composite KEM pairs ML-KEM with a traditional KEM (here ML-KEM-768 with ECDH over P-256) so the
 * derived secret is secure as long as <i>either</i> component remains unbroken. The provider exposes
 * each composite parameter set under its algorithm name (e.g. {@code MLKEM768-ECDH-P256-SHA3-256})
 * and its OID; this example uses the name.
 */
public class CompositeKEMExample
{
    private static final String COMPOSITE_ALG = "MLKEM768-ECDH-P256-SHA3-256";

    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        // 1. Generate a composite key pair. The public/private keys are composites whose components
        //    are, in order, the ML-KEM-768 key and the ECDH P-256 key.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(COMPOSITE_ALG, "BC");
        KeyPair kp = kpg.generateKeyPair();

        // 2. Sender: encapsulate. KeyGenerator with a KEMGenerateSpec produces the shared secret as
        //    a SecretKey together with the encapsulation (ciphertext) to transmit to the recipient.
        //    withNoKdf() uses the composite KEM shared secret (SHA3-256 output) directly as the key.
        KeyGenerator sender = KeyGenerator.getInstance(COMPOSITE_ALG, "BC");
        sender.init(new KEMGenerateSpec.Builder(kp.getPublic(), "AES", 256).withNoKdf().build());
        SecretKeyWithEncapsulation encapsulated = (SecretKeyWithEncapsulation)sender.generateKey();

        byte[] sharedSecret = encapsulated.getEncoded();
        byte[] ciphertext = encapsulated.getEncapsulation();

        // 3. Recipient: decapsulate using the private key and the received ciphertext.
        KeyGenerator recipient = KeyGenerator.getInstance(COMPOSITE_ALG, "BC");
        recipient.init(new KEMExtractSpec.Builder(kp.getPrivate(), ciphertext, "AES", 256).withNoKdf().build());
        SecretKeyWithEncapsulation decapsulated = (SecretKeyWithEncapsulation)recipient.generateKey();

        byte[] recoveredSecret = decapsulated.getEncoded();

        System.out.println("algorithm        : " + COMPOSITE_ALG);
        System.out.println("ciphertext length: " + ciphertext.length + " bytes");
        System.out.println("sender secret    : " + Hex.toHexString(sharedSecret));
        System.out.println("recipient secret : " + Hex.toHexString(recoveredSecret));

        if (!Arrays.constantTimeAreEqual(sharedSecret, recoveredSecret))
        {
            throw new IllegalStateException("shared secrets do not match");
        }

        System.out.println("shared secrets match - the AES-256 key can now be used to protect data.");
    }
}
