package org.bouncycastle.openpgp.examples;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Date;

import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
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
 * A simple utility class that generates a public/secret keyring containing a DSA signing
 * key and an El Gamal key for encryption.
 * <p>
 * usage: DSAElGamalKeyRingGenerator [-a] identity passPhrase
 * <p>
 * Where identity is the name to be associated with the public key. The keys are placed
 * in the files pub.[asc|bpg] and secret.[asc|bpg].
 */
public class DSAElGamalKeyRingGenerator
{

    private static final int SIG_HASH = HashAlgorithmTags.SHA512;
    private static final int[] HASH_PREFERENCES = new int[]{
        HashAlgorithmTags.SHA512, HashAlgorithmTags.SHA384, HashAlgorithmTags.SHA256, HashAlgorithmTags.SHA224
    };
    private static final int[] SYM_PREFERENCES = new int[]{
        SymmetricKeyAlgorithmTags.AES_256, SymmetricKeyAlgorithmTags.AES_192, SymmetricKeyAlgorithmTags.AES_128
    };
    private static final int[] COMP = new int[]{
        CompressionAlgorithmTags.ZLIB, CompressionAlgorithmTags.BZIP2, CompressionAlgorithmTags.ZLIB, CompressionAlgorithmTags.UNCOMPRESSED
    };

    private static void exportKeyPair(
        OutputStream secretOut,
        OutputStream publicOut,
        KeyPair dsaKp,
        KeyPair elgKp,
        String identity,
        char[] passPhrase,
        boolean armor)
        throws IOException, PGPException
    {
        if (armor)
        {
            secretOut = new ArmoredOutputStream(secretOut);
        }

        PGPKeyPair dsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, dsaKp, new Date());
        PGPKeyPair elgKeyPair = new JcaPGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, elgKp, new Date());
        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);

        PGPContentSignerBuilder contentSignerBuilder = new JcaPGPContentSignerBuilder(
            dsaKeyPair.getPublicKey().getAlgorithm(), SIG_HASH);
        PBESecretKeyEncryptor secretKeyEncryptor = new JcePBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256, sha1Calc)
            .setProvider("BC")
            .build(passPhrase);

        PGPSignatureSubpacketGenerator primaryHashedSubpackets = getPrimaryKeyHashedSubpackets();
        primaryHashedSubpackets.setIssuerFingerprint(false, dsaKeyPair.getPublicKey());
        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, dsaKeyPair,
            identity, sha1Calc, primaryHashedSubpackets.generate(), null, contentSignerBuilder, secretKeyEncryptor);

        PGPSignatureSubpacketGenerator subkeyHashedSubpackets = getEncryptionKeyHashedSubpackets();
        subkeyHashedSubpackets.setIssuerFingerprint(false, dsaKeyPair.getPublicKey());
        keyRingGen.addSubKey(elgKeyPair, subkeyHashedSubpackets.generate(), null);

        keyRingGen.generateSecretKeyRing().encode(secretOut);

        secretOut.close();

        if (armor)
        {
            publicOut = new ArmoredOutputStream(publicOut);
        }

        keyRingGen.generatePublicKeyRing().encode(publicOut);

        publicOut.close();
    }

    private static PGPSignatureSubpacketGenerator getEncryptionKeyHashedSubpackets()
    {
        PGPSignatureSubpacketGenerator gen = new PGPSignatureSubpacketGenerator();
        gen.setKeyFlags(true, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);
        return gen;
    }

    private static PGPSignatureSubpacketGenerator getPrimaryKeyHashedSubpackets()
    {
        PGPSignatureSubpacketGenerator gen = new PGPSignatureSubpacketGenerator();
        gen.setPreferredHashAlgorithms(false, HASH_PREFERENCES);
        gen.setPreferredSymmetricAlgorithms(false, SYM_PREFERENCES);
        gen.setPreferredCompressionAlgorithms(false, COMP);
        gen.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);
        gen.setKeyFlags(true, KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA);
        return gen;
    }

    private static KeyPair generateElGamalKeyPair()
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
    {
        KeyPairGenerator elgKpg = KeyPairGenerator.getInstance("ELGAMAL", "BC");
        // 3072 bit parameters from https://datatracker.ietf.org/doc/html/rfc3526#section-4
        BigInteger g = new BigInteger("2", 16);
        BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF", 16);

        DHParameterSpec elParams = new DHParameterSpec(p, g);

        elgKpg.initialize(elParams);

        //
        // this is quicker because we are using pregenerated parameters.
        //
        KeyPair elgKp = elgKpg.generateKeyPair();
        return elgKp;
    }

    private static KeyPair generateDSAKeyPair()
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        KeyPairGenerator dsaKpg = KeyPairGenerator.getInstance("DSA", "BC");

        dsaKpg.initialize(3072);

        //
        // this takes a while as the key generator has to generate some DSA params
        // before it generates the key.
        //
        KeyPair dsaKp = dsaKpg.generateKeyPair();
        return dsaKp;
    }

    public static void main(
        String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        if (args.length < 2)
        {
            System.out.println("DSAElGamalKeyRingGenerator [-a] identity passPhrase");
            System.exit(0);
        }

        KeyPair dsaKp = generateDSAKeyPair();

        KeyPair elgKp = generateElGamalKeyPair();

        if (args[0].equals("-a"))
        {
            if (args.length < 3)
            {
                System.out.println("DSAElGamalKeyRingGenerator [-a] identity passPhrase");
                System.exit(0);
            }

            FileOutputStream out1 = new FileOutputStream("secret.asc");
            FileOutputStream out2 = new FileOutputStream("pub.asc");

            exportKeyPair(out1, out2, dsaKp, elgKp, args[1], args[2].toCharArray(), true);
        }
        else
        {
            FileOutputStream out1 = new FileOutputStream("secret.bpg");
            FileOutputStream out2 = new FileOutputStream("pub.bpg");

            exportKeyPair(out1, out2, dsaKp, elgKp, args[0], args[1].toCharArray(), false);
        }
    }
}
