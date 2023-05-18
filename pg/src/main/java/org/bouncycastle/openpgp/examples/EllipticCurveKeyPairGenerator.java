package org.bouncycastle.openpgp.examples;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

/**
 * A simple utility class that generates an RSA key ring.
 * <p>
 * usage: RSAKeyPairGenerator [-a] identity passPhrase
 * <p>
 * Where identity is the name to be associated with the public key. The keys are placed
 * in the files pub.[asc|bpg] and secret.[asc|bpg].
 */
public class EllipticCurveKeyPairGenerator
{

    private static final int SIG_HASH = HashAlgorithmTags.SHA512;
    private static final int[] HASH_PREFERENCES = new int[]{
        HashAlgorithmTags.SHA512, HashAlgorithmTags.SHA384, HashAlgorithmTags.SHA256, HashAlgorithmTags.SHA224
    };
    private static final int[] SYM_PREFERENCES = new int[]{
        SymmetricKeyAlgorithmTags.AES_256, SymmetricKeyAlgorithmTags.AES_192, SymmetricKeyAlgorithmTags.AES_128
    };
    private static final int[] COMP_PREFERENCES = new int[]{
        CompressionAlgorithmTags.ZLIB, CompressionAlgorithmTags.BZIP2, CompressionAlgorithmTags.ZLIB, CompressionAlgorithmTags.UNCOMPRESSED
    };

    private static void generateAndExportKeyRing(
        OutputStream secretOut,
        OutputStream publicOut,
        String identity,
        char[] passPhrase,
        boolean armor)
        throws IOException, NoSuchProviderException, PGPException, NoSuchAlgorithmException, InvalidAlgorithmParameterException
    {
        if (armor)
        {
            secretOut = new ArmoredOutputStream(secretOut);
        }

        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);

        KeyPairGenerator eddsaGen = KeyPairGenerator.getInstance("EdDSA", "BC");
        KeyPairGenerator xdhGen = KeyPairGenerator.getInstance("XDH", "BC");

        PGPContentSignerBuilder contentSignerBuilder = new JcaPGPContentSignerBuilder(PublicKeyAlgorithmTags.EDDSA_LEGACY, SIG_HASH);
        PBESecretKeyEncryptor secretKeyEncryptor = new JcePBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256, sha1Calc)
            .build(passPhrase);

        Date now = new Date();

        eddsaGen.initialize(new ECNamedCurveGenParameterSpec("ed25519"));
        KeyPair primaryKP = eddsaGen.generateKeyPair();
        PGPKeyPair primaryKey = new JcaPGPKeyPair(PGPPublicKey.EDDSA_LEGACY, primaryKP, now);
        PGPSignatureSubpacketGenerator primarySubpackets = new PGPSignatureSubpacketGenerator();
        primarySubpackets.setKeyFlags(true, KeyFlags.CERTIFY_OTHER);
        primarySubpackets.setPreferredHashAlgorithms(false, HASH_PREFERENCES);
        primarySubpackets.setPreferredSymmetricAlgorithms(false, SYM_PREFERENCES);
        primarySubpackets.setPreferredCompressionAlgorithms(false, COMP_PREFERENCES);
        primarySubpackets.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);
        primarySubpackets.setIssuerFingerprint(false, primaryKey.getPublicKey());

        eddsaGen.initialize(new ECNamedCurveGenParameterSpec("ed25519"));
        KeyPair signingKP = eddsaGen.generateKeyPair();
        PGPKeyPair signingKey = new JcaPGPKeyPair(PGPPublicKey.EDDSA_LEGACY, signingKP, now);
        PGPSignatureSubpacketGenerator signingKeySubpacket = new PGPSignatureSubpacketGenerator();
        signingKeySubpacket.setKeyFlags(true, KeyFlags.SIGN_DATA);
        signingKeySubpacket.setIssuerFingerprint(false, primaryKey.getPublicKey());

        xdhGen.initialize(new ECNamedCurveGenParameterSpec("X25519"));
        KeyPair encryptionKP = xdhGen.generateKeyPair();
        PGPKeyPair encryptionKey = new JcaPGPKeyPair(PGPPublicKey.ECDH, encryptionKP, now);
        PGPSignatureSubpacketGenerator encryptionKeySubpackets = new PGPSignatureSubpacketGenerator();
        encryptionKeySubpackets.setKeyFlags(true, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);
        encryptionKeySubpackets.setIssuerFingerprint(false, primaryKey.getPublicKey());

        PGPKeyRingGenerator gen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, primaryKey, identity,
            sha1Calc, primarySubpackets.generate(), null, contentSignerBuilder, secretKeyEncryptor);
        gen.addSubKey(signingKey, signingKeySubpacket.generate(), null, contentSignerBuilder);
        gen.addSubKey(encryptionKey, encryptionKeySubpackets.generate(), null);

        PGPSecretKeyRing secretKeys = gen.generateSecretKeyRing();
        secretKeys.encode(secretOut);

        secretOut.close();

        if (armor)
        {
            publicOut = new ArmoredOutputStream(publicOut);
        }

        List<PGPPublicKey> publicKeyList = new ArrayList<PGPPublicKey>();
        Iterator<PGPPublicKey> it = secretKeys.getPublicKeys();
        while (it.hasNext())
        {
            publicKeyList.add(it.next());
        }

        PGPPublicKeyRing publicKeys = new PGPPublicKeyRing(publicKeyList);

        publicKeys.encode(publicOut);

        publicOut.close();
    }

    public static void main(
        String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        if (args.length < 2)
        {
            System.out.println("EllipticCurveKeyPairGenerator [-a] identity passPhrase");
            System.exit(0);
        }

        if (args[0].equals("-a"))
        {
            if (args.length < 3)
            {
                System.out.println("EllipticCurveKeyPairGenerator [-a] identity passPhrase");
                System.exit(0);
            }

            FileOutputStream out1 = new FileOutputStream("secret.asc");
            FileOutputStream out2 = new FileOutputStream("pub.asc");

            generateAndExportKeyRing(out1, out2, args[1], args[2].toCharArray(), true);
        }
        else
        {
            FileOutputStream out1 = new FileOutputStream("secret.bpg");
            FileOutputStream out2 = new FileOutputStream("pub.bpg");

            generateAndExportKeyRing(out1, out2, args[0], args[1].toCharArray(), false);
        }
    }
}
