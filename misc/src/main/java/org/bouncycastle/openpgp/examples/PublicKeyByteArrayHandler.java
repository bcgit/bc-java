package org.bouncycastle.openpgp.examples;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

/**
 * Byte-array in / byte-array out public-key OpenPGP encryption &mdash; the
 * combination of {@link ByteArrayHandler} (which only covers the passphrase
 * case) and {@link KeyBasedFileProcessor} (which only covers files) that
 * github issue #1414 was looking for.
 * <p>
 * The static {@link #encrypt encrypt} and {@link #decrypt decrypt} methods
 * accept and return plain {@code byte[]}; no temporary files or
 * {@link PGPUtil#writeFileToLiteralData PGPUtil.writeFileToLiteralData}
 * detour is required. The wire format follows the standard OpenPGP packet
 * sequence so output produced here is interchangeable with output produced by any
 * other RFC 4880 / RFC 9580 implementation and the recipient does not need
 * to be aware that the source was a byte array rather than a file.
 * <p>
 * {@code main} demonstrates a complete round-trip end-to-end: it builds a
 * transient RSA-2048 PGP key pair in-process, encrypts a sample message
 * with the public key, decrypts with the corresponding secret key, and
 * checks that the recovered bytes match the original.
 */
public class PublicKeyByteArrayHandler
{
    /**
     * Encrypt a byte array using the supplied OpenPGP public key.
     *
     * @param clearData          the bytes to be encrypted.
     * @param encKey             the recipient's OpenPGP public key. Must be a key flagged
     *                           for encryption use (encryption / encrypt-storage subkey).
     * @param fileName           value to record in the inner LiteralData "filename"
     *                           field. Pass {@link PGPLiteralData#CONSOLE} when there
     *                           is no meaningful filename to record.
     * @param armor              when true, the output is ASCII-armored ("-----BEGIN PGP
     *                           MESSAGE-----" etc.); when false, the output is raw
     *                           binary OpenPGP packets.
     * @param withIntegrityCheck when true, the SymmetricallyEncryptedIntegrityProtected
     *                           packet form (with MDC) is used &mdash; recommended for
     *                           all new traffic.
     * @return the encrypted bytes.
     */
    public static byte[] encrypt(
        byte[] clearData,
        PGPPublicKey encKey,
        String fileName,
        boolean armor,
        boolean withIntegrityCheck)
        throws IOException, PGPException
    {
        if (fileName == null)
        {
            fileName = PGPLiteralData.CONSOLE;
        }

        // Compression could be added here too if required.
        byte[] literalData = createLiteralData(clearData, fileName);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream out = bOut;
        if (armor)
        {
            out = new ArmoredOutputStream(out);
        }

        PGPDataEncryptorBuilder encryptorBuilder = new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256)
            .setProvider("BC")
            .setSecureRandom(new SecureRandom())
            .setWithIntegrityPacket(withIntegrityCheck);

        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(encryptorBuilder);
        encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC"));

        OutputStream encOut = encGen.open(out, literalData.length);
        encOut.write(literalData);
        encOut.close();

        if (armor)
        {
            out.close();
        }

        return bOut.toByteArray();
    }

    /**
     * Decrypt a byte array using a passphrase-protected OpenPGP secret key
     * ring collection. The first encrypted-data packet whose key ID matches
     * an entry in {@code secretKeys} is the one that drives decryption.
     *
     * @param encrypted   the encrypted bytes (ASCII-armored or raw binary &mdash;
     *                    {@link PGPUtil#getDecoderStream} sorts that out).
     * @param secretKeys  the recipient's secret key ring collection.
     * @param passPhrase  passphrase protecting the recipient's secret key.
     * @return the decrypted bytes.
     */
    public static byte[] decrypt(
        byte[] encrypted,
        PGPSecretKeyRingCollection secretKeys,
        char[] passPhrase)
        throws IOException, PGPException
    {
        InputStream in = PGPUtil.getDecoderStream(new ByteArrayInputStream(encrypted));

        JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(in);
        Object o = pgpF.nextObject();

        // The first object might be a marker packet.
        PGPEncryptedDataList enc =
            (o instanceof PGPEncryptedDataList) ? (PGPEncryptedDataList)o
                                                : (PGPEncryptedDataList)pgpF.nextObject();

        // Find the encrypted-data packet whose key ID we have a matching
        // private key for.
        PGPPrivateKey sKey = null;
        PGPPublicKeyEncryptedData pbe = null;
        for (Iterator it = enc.getEncryptedDataObjects(); sKey == null && it.hasNext(); )
        {
            pbe = (PGPPublicKeyEncryptedData)it.next();

            PGPSecretKey pgpSecKey = secretKeys.getSecretKey(pbe.getKeyID());
            if (pgpSecKey != null)
            {
                sKey = pgpSecKey.extractPrivateKey(
                    new JcePBESecretKeyDecryptorBuilder()
                        .setProvider("BC")
                        .build(passPhrase));
            }
        }

        if (sKey == null)
        {
            throw new IllegalArgumentException("secret key for message not found.");
        }

        InputStream clear = pbe.getDataStream(
            new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey));

        JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);
        Object message = plainFact.nextObject();

        // The inner packet sequence is usually CompressedData -> LiteralData,
        // but some producers skip compression.
        if (message instanceof PGPCompressedData)
        {
            JcaPGPObjectFactory innerFact =
                new JcaPGPObjectFactory(((PGPCompressedData)message).getDataStream());
            message = innerFact.nextObject();
        }

        if (!(message instanceof PGPLiteralData))
        {
            throw new PGPException("unexpected packet at top of encrypted message: "
                + message.getClass().getName());
        }

        byte[] plain = Streams.readAll(((PGPLiteralData)message).getInputStream());

        if (pbe.isIntegrityProtected() && !pbe.verify())
        {
            throw new PGPException("message failed integrity check");
        }

        return plain;
    }

    private static byte[] createLiteralData(byte[] clearData, String fileName)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();


        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        OutputStream pOut = lData.open(bOut, PGPLiteralData.BINARY, fileName,
            clearData.length, new Date());
        pOut.write(clearData);
        pOut.close();

        return bOut.toByteArray();
    }

    /**
     * Convenience: build a minimal in-memory PGP secret key ring carrying a
     * single RSA encryption key under the supplied passphrase. The matching
     * public key can be pulled out with {@code ring.getPublicKey()}; the
     * containing collection for {@code decrypt} is just
     * {@code new PGPSecretKeyRingCollection(java.util.Collections.singletonList(ring))}.
     */
    private static PGPSecretKeyRing makeRsaKeyRing(String identity, char[] passPhrase, int keySize)
        throws Exception
    {
        PGPDigestCalculator sha1Calc =
            new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(keySize);
        KeyPair kp = kpg.generateKeyPair();
        PGPKeyPair pgpKey = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, kp, new Date());

        PGPKeyRingGenerator ringGen = new PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION,
            pgpKey,
            identity,
            sha1Calc,
            null,
            null,
            new JcaPGPContentSignerBuilder(pgpKey.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256)
                .setProvider("BC"),
            new JcePBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256, sha1Calc)
                .setProvider("BC").build(passPhrase));

        return ringGen.generateSecretKeyRing();
    }

    public static void main(String[] args)
        throws Exception
    {
        // -DM 48 System.out.print
        Security.addProvider(new BouncyCastleProvider());

        char[] passPhrase = "demo-passphrase".toCharArray();
        PGPSecretKeyRing secretRing = makeRsaKeyRing("Test User <test@example.org>", passPhrase, 2048);
        PGPSecretKeyRingCollection secretRings = new PGPSecretKeyRingCollection(
            java.util.Collections.singletonList(secretRing));

        // The primary RSA_GENERAL key produced by makeRsaKeyRing is usable
        // for both signing and encryption; pull it out as the recipient key.
        PGPPublicKey encKey = secretRing.getPublicKey();

        byte[] original = "Hello, OpenPGP byte-array encryption!".getBytes("UTF-8");

        byte[] encrypted = encrypt(original, encKey, PGPLiteralData.CONSOLE, true, true);
        byte[] roundTrip = decrypt(encrypted, secretRings, passPhrase);

        System.out.println("plaintext  : " + new String(original, "UTF-8"));
        System.out.println("encrypted (" + encrypted.length + " bytes, armored):");
        System.out.println(new String(encrypted, "UTF-8"));
        System.out.println("recovered  : " + new String(roundTrip, "UTF-8"));

        if (!Arrays.areEqual(original, roundTrip))
        {
            throw new IllegalStateException("byte-array PGP round-trip failed");
        }
        System.out.println("round-trip OK");
    }
}
