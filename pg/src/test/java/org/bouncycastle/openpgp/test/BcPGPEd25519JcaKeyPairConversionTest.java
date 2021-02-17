package org.bouncycastle.openpgp.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Date;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyConverter;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;

public class BcPGPEd25519JcaKeyPairConversionTest
    extends SimpleTest
{
    private static final byte[] pub1 = Base64.decode("MCowBQYDK2VwAyEAZ7K+dI+lVbTcq5o6U2iPcZ7M/wEYECbgy2/E5uqjEN8=");
    private static final byte[] priv1 = Base64.decode("MFECAQEwBQYDK2VwBCIEIPtUlmZHsIy0D1dlzWIDfrNBtgzZhIfs1VOTWDUHRmBtgSEAZ7K+dI+lVbTcq5o6U2iPcZ7M/wEYECbgy2/E5uqjEN8=");
    private static final byte[] pub2 = Base64.decode("MCowBQYDK2VwAyEAnw8ZpX+h2yGlnPN85QAlP1LPtw/Onh2ojL5Tlmci66o=");
    private static final byte[] priv2 = Base64.decode("MFECAQEwBQYDK2VwBCIEIADsCDTn0Ejbt05TJp4lN9/cp04lyugTygx67s+Q6mzygSEAnw8ZpX+h2yGlnPN85QAlP1LPtw/Onh2ojL5Tlmci66o=");

    public String getName()
    {
        return "Ed25519KeyConvert";
    }

    public void performTest()
        throws Exception
    {
        KeyFactory keyFact = KeyFactory.getInstance("ed25519", new BouncyCastleProvider());

        convertEd25519KeyFromJcaPGPKeyPairToBcPGPKeyPair(keyFact.generatePublic(new X509EncodedKeySpec(pub1)), keyFact.generatePrivate(new PKCS8EncodedKeySpec(priv1)));
        convertEd25519KeyFromJcaPGPKeyPairToBcPGPKeyPair(keyFact.generatePublic(new X509EncodedKeySpec(pub2)), keyFact.generatePrivate(new PKCS8EncodedKeySpec(priv2)));
    }

    public static void convertEd25519KeyFromJcaPGPKeyPairToBcPGPKeyPair(PublicKey pubKey, PrivateKey privKey) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, PGPException {
        Date creationDate = new Date();
        int algorithm = PublicKeyAlgorithmTags.EDDSA;

        KeyPair keyPair = new KeyPair(pubKey, privKey);
        
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

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new BcPGPEd25519JcaKeyPairConversionTest());
    }
}
