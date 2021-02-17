package org.bouncycastle.openpgp.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Date;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyConverter;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;

public class Ed25519JcaPGPKeyPairToBcPGPKeyPairConversionTest {

    public static void main(String[] args) throws Exception {
        for (int i = 0; i < 1000; i++) {
            convertEd25519KeyFromJcaPGPKeyPairToBcPGPKeyPair();
        }
    }

    public static void convertEd25519KeyFromJcaPGPKeyPairToBcPGPKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, PGPException {
        Date creationDate = new Date();
        int algorithm = PublicKeyAlgorithmTags.EDDSA;
        KeyPairGenerator certKeyGenerator = KeyPairGenerator.getInstance("ed25519", new BouncyCastleProvider());
        certKeyGenerator.initialize(new ECNamedCurveGenParameterSpec("ed25519"));
        KeyPair keyPair = certKeyGenerator.generateKeyPair();

        BcPGPKeyConverter converter = new BcPGPKeyConverter();
        PGPKeyPair jcaPgpPair = new JcaPGPKeyPair(algorithm, keyPair, creationDate);
        AsymmetricKeyParameter publicKey = converter.getPublicKey(jcaPgpPair.getPublicKey());
        AsymmetricKeyParameter privateKey = converter.getPrivateKey(jcaPgpPair.getPrivateKey()); // This line threw previously.
        AsymmetricCipherKeyPair asymKeyPair = new AsymmetricCipherKeyPair(publicKey, privateKey);

        PGPKeyPair bcKeyPair = new BcPGPKeyPair(algorithm, asymKeyPair, creationDate);

        if (!Arrays.equals(jcaPgpPair.getPrivateKey().getPrivateKeyDataPacket().getEncoded(),
                bcKeyPair.getPrivateKey().getPrivateKeyDataPacket().getEncoded())) {
            throw new PGPException("JcaPGPKeyPair and BcPGPKeyPair private keys are not equal.");
        }
    }
}
