package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.test.AbstractPacketTest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.util.encoders.Hex;

import java.security.*;
import java.security.spec.*;
import java.util.Date;

public class EdDSAKeyConversionWithLeadingZeroTest
        extends AbstractPacketTest
{
    @Override
    public String getName()
    {
        return "EdDSALeadingZero";
    }

    private static final String ED448_KEY_WITH_LEADING_ZERO = "308183020101300506032b6571043b0439fe2c82fd07b0e8b5da002ee4964e55a357bfdd2192fe43a40b150e6c5a8f8202f140dd34ede17dc10fef9a98bf8188425c14bd1a76a308cfb7813a0000728cbb07c590e2cb282834cc22d7a1f775f729986c4754e7035695dee34057403e98e94cf5012007c3236f4894af039e668acb746fcf8a00";
    private static final String ED448_PUB_WITH_LEADING_ZERO = "3043300506032b6571033a0000728cbb07c590e2cb282834cc22d7a1f775f729986c4754e7035695dee34057403e98e94cf5012007c3236f4894af039e668acb746fcf8a00";

    private static final String ED25519_KEY_WITH_LEADING_ZERO = "3051020101300506032b65700422042077ee5931a6d454f85acd9cc28bb2fa8c340e10f7cbf0193f1f898a5c22e77f4281210000dcd38e8ec0978690a4bbc8ac7787d311e741c394ba839ad9cc15e9ba21deb1";
    private static final String ED25519_PUB_WITH_LEADING_ZERO = "302a300506032b657003210000dcd38e8ec0978690a4bbc8ac7787d311e741c394ba839ad9cc15e9ba21deb1";

    @Override
    public void performTest()
            throws Exception
    {
        testWithEd448KeyWithLeadingZero();
        testWithEd25519KeyWithLeadingZero();
    }

    private void testWithEd448KeyWithLeadingZero()
            throws NoSuchAlgorithmException, InvalidKeySpecException, PGPException, InvalidKeyException, SignatureException
    {
        JcaPGPKeyConverter jcaPGPKeyConverter = new JcaPGPKeyConverter().setProvider(new BouncyCastleProvider());

        KeyFactory factory = KeyFactory.getInstance("EdDSA", new BouncyCastleProvider());

        PublicKey pubKey = factory.generatePublic(new X509EncodedKeySpec(Hex.decode(ED448_PUB_WITH_LEADING_ZERO)));
        PrivateKey privKey = factory.generatePrivate(new PKCS8EncodedKeySpec(Hex.decode(ED448_KEY_WITH_LEADING_ZERO)));
        KeyPair keyPair = new KeyPair(pubKey, privKey);

        Date creationDate = new Date();
        PGPKeyPair jcaPgpPair = new JcaPGPKeyPair(PublicKeyAlgorithmTags.Ed448, keyPair, creationDate);
        isTrue("public key encoding before conversion MUST have leading 0",
                jcaPgpPair.getPublicKey().getPublicKeyPacket().getKey().getEncoded()[0] == 0); // leading 0

        PublicKey cPubKey = jcaPGPKeyConverter.getPublicKey(jcaPgpPair.getPublicKey());
        PrivateKey cPrivKey = jcaPGPKeyConverter.getPrivateKey(jcaPgpPair.getPrivateKey());

        testSignature(cPrivKey, pubKey, "Ed448");
        testSignature(privKey, cPubKey, "Ed448");

        jcaPgpPair = new JcaPGPKeyPair(PublicKeyAlgorithmTags.Ed448, new KeyPair(cPubKey, cPrivKey), creationDate);
        isTrue("public key encoding after conversion MUST have leading 0",
                jcaPgpPair.getPublicKey().getPublicKeyPacket().getKey().getEncoded()[0] == 0); // leading 0 is preserved
    }


    private void testWithEd25519KeyWithLeadingZero()
            throws NoSuchAlgorithmException, InvalidKeySpecException, PGPException, InvalidKeyException, SignatureException
    {
        JcaPGPKeyConverter jcaPGPKeyConverter = new JcaPGPKeyConverter().setProvider(new BouncyCastleProvider());

        KeyFactory factory = KeyFactory.getInstance("EdDSA", new BouncyCastleProvider());

        PublicKey pubKey = factory.generatePublic(new X509EncodedKeySpec(Hex.decode(ED25519_PUB_WITH_LEADING_ZERO)));
        PrivateKey privKey = factory.generatePrivate(new PKCS8EncodedKeySpec(Hex.decode(ED25519_KEY_WITH_LEADING_ZERO)));
        KeyPair keyPair = new KeyPair(pubKey, privKey);

        Date creationDate = new Date();
        PGPKeyPair jcaPgpPair = new JcaPGPKeyPair(PublicKeyAlgorithmTags.Ed25519, keyPair, creationDate);
        isTrue("public key encoding before conversion MUST have leading 0",
                jcaPgpPair.getPublicKey().getPublicKeyPacket().getKey().getEncoded()[0] == 0); // leading 0

        PublicKey cPubKey = jcaPGPKeyConverter.getPublicKey(jcaPgpPair.getPublicKey());
        PrivateKey cPrivKey = jcaPGPKeyConverter.getPrivateKey(jcaPgpPair.getPrivateKey());

        testSignature(cPrivKey, pubKey, "Ed25519");
        testSignature(privKey, cPubKey, "Ed25519");

        jcaPgpPair = new JcaPGPKeyPair(PublicKeyAlgorithmTags.Ed25519, new KeyPair(cPubKey, cPrivKey), creationDate);
        isTrue("public key encoding after conversion MUST have leading 0",
                jcaPgpPair.getPublicKey().getPublicKeyPacket().getKey().getEncoded()[0] == 0); // leading 0 is preserved
    }

    private void testSignature(PrivateKey privateKey, PublicKey publicKey, String edAlgo)
            throws NoSuchAlgorithmException, SignatureException, InvalidKeyException
    {
        Signature signature = Signature.getInstance(edAlgo, new BouncyCastleProvider());
        signature.initSign(privateKey);
        signature.update("Hello, World!\n".getBytes());
        byte[] sig = signature.sign();

        signature.initVerify(publicKey);
        signature.update("Hello, World!\n".getBytes());
        isTrue("Signature MUST verify", signature.verify(sig));
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());
        runTest(new EdDSAKeyConversionWithLeadingZeroTest());
    }
}
