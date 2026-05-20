package org.bouncycastle.crypto.examples;

import java.security.SecureRandom;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.KeyEncoder;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.IESEngine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.EphemeralKeyPairGenerator;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.IESWithCipherParameters;
import org.bouncycastle.crypto.parsers.ECIESPublicKeyParser;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * Example: ECIES with SHA-256 KDF, HMAC-SHA-256 and AES-128 in <b>ECB</b> mode,
 * over secp256k1.
 * <p>
 * <b>Read this before using.</b> ECB mode is <b>not</b> a standards-compliant
 * symmetric-cipher choice for ECIES &mdash; IEEE Std 1363a-2004 sec. 11,
 * ISO/IEC 18033-2 and SECG SEC 1 v2 sec. 5.1 all enumerate either the
 * KDF-stream (XOR) form or a CBC-mode block cipher. ECB doesn't hide plaintext
 * patterns; combining it with ECIES weakens what the construction is meant to
 * provide. The BC JCE provider therefore deliberately does <b>not</b> register a
 * named {@code Cipher} alias of the form {@code ECIESwithSHA256andAES-ECB} (see
 * github issue #1095). For production work prefer
 * {@code Cipher.getInstance("ECIESwithSHA256andAES-CBC", "BC")} or the
 * stream-cipher form {@code Cipher.getInstance("ECIESwithSHA256", "BC")}.
 * <p>
 * This example only exists to show how a caller who <i>must</i> interop with an
 * external system that uses AES-ECB-mode ECIES can build the construction
 * locally via the lightweight {@link IESEngine} API. The wire layout produced
 * here is V || C || T (uncompressed ephemeral public key || ECB ciphertext ||
 * HMAC-SHA-256 tag), matching the IEEE 1363a triple emitted by BC's other
 * ECIES forms; wire-format compatibility with any specific external library
 * (e.g. the npm {@code standard-ecies} package) is <i>not</i> claimed here, as
 * such libraries typically use their own byte ordering and may derive the
 * cipher and MAC keys from the KDF stream in a different order. Interop with a
 * given external library requires matching its exact bytes-on-the-wire format
 * on top of getting the crypto primitives right; this example only
 * demonstrates the primitives.
 */
public class ECIESAESECBExample
{
    public static void main(String[] args)
        throws Exception
    {
        // -DM 48 System.out.print
        SecureRandom random = new SecureRandom();

        // 1. Pick the curve. secp256k1 here matches the npm standard-ecies default;
        //    any curve supported by BC works.
        X9ECParameters x9 = SECNamedCurves.getByName("secp256k1");
        final ECDomainParameters domain = new ECDomainParameters(
            x9.getCurve(), x9.getG(), x9.getN(), x9.getH(), x9.getSeed());

        // 2. Bob: long-term receiver key pair.
        ECKeyPairGenerator kpg = new ECKeyPairGenerator();
        kpg.init(new ECKeyGenerationParameters(domain, random));
        AsymmetricCipherKeyPair bobKeyPair = kpg.generateKeyPair();

        byte[] message = "Hello, ECIES.".getBytes("UTF-8");
        System.out.println("plaintext : " + new String(message, "UTF-8"));

        // 3. Shared IES parameters. AES-128 ECB: no IV, 128-bit cipher key,
        //    128-bit MAC key for HMAC-SHA-256.
        final IESWithCipherParameters iesParams = new IESWithCipherParameters(
            null,    // optional derivation parameter
            null,    // optional encoding parameter
            128,     // MAC key size, in bits
            128);    // cipher key size, in bits  (AES-128)

        // 4. Alice encrypts to Bob. The EphemeralKeyPairGenerator is what makes
        //    the IESEngine prepend the ephemeral public key V to its output.
        byte[] ciphertext;
        {
            ECKeyPairGenerator ephGen = new ECKeyPairGenerator();
            ephGen.init(new ECKeyGenerationParameters(domain, random));

            EphemeralKeyPairGenerator ephemeralGen = new EphemeralKeyPairGenerator(
                ephGen,
                new KeyEncoder()
                {
                    public byte[] getEncoded(AsymmetricKeyParameter k)
                    {
                        // Uncompressed point format to match the npm
                        // standard-ecies default; switch to true here for
                        // compressed.
                        return ((ECPublicKeyParameters)k).getQ().getEncoded(false);
                    }
                });

            IESEngine engine = newIESEngine();
            engine.init(bobKeyPair.getPublic(), iesParams, ephemeralGen);
            ciphertext = engine.processBlock(message, 0, message.length);
        }
        System.out.println("ciphertext: " + Hex.toHexString(ciphertext));

        // 5. Bob decrypts. The ECIESPublicKeyParser strips V off the front of
        //    the ciphertext and reconstructs the sender's ephemeral public key.
        byte[] roundTrip;
        {
            IESEngine engine = newIESEngine();
            engine.init(bobKeyPair.getPrivate(), iesParams, new ECIESPublicKeyParser(domain));
            roundTrip = engine.processBlock(ciphertext, 0, ciphertext.length);
        }
        System.out.println("recovered : " + new String(roundTrip, "UTF-8"));

        if (!Arrays.areEqual(message, roundTrip))
        {
            throw new IllegalStateException("ECIES + AES-ECB round-trip failed");
        }
        System.out.println("round-trip OK");
    }

    /**
     * AES in ECB mode wrapped in a PKCS#7-padding {@link BufferedBlockCipher},
     * configured as the symmetric cipher for {@link IESEngine}. PKCS#7 padding
     * is what BC's existing {@code ECIESwithAES-CBC} JCE registration uses
     * under the hood and what most external libraries (including the npm
     * {@code standard-ecies} package) emit for AES-ECB ECIES.
     */
    private static IESEngine newIESEngine()
    {
        BufferedBlockCipher aesEcb = new PaddedBufferedBlockCipher(AESEngine.newInstance());
        return new IESEngine(
            new ECDHBasicAgreement(),
            new KDF2BytesGenerator(new SHA256Digest()),
            new HMac(new SHA256Digest()),
            aesEcb);
    }
}
