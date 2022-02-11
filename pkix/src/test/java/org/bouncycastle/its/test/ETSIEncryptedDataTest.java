package org.bouncycastle.its.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

import junit.framework.TestCase;
import org.bouncycastle.its.ETSIEncryptedData;
import org.bouncycastle.its.ETSIEncryptedDataBuilder;
import org.bouncycastle.its.ETSIRecipientID;
import org.bouncycastle.its.ETSIRecipientInfo;
import org.bouncycastle.its.ETSIRecipientInfoBuilder;
import org.bouncycastle.its.jcajce.JcaETSIDataDecryptor;
import org.bouncycastle.its.jcajce.JceETSIDataEncryptor;
import org.bouncycastle.its.jcajce.JceETSIKeyWrapper;
import org.bouncycastle.its.operator.ETSIDataDecryptor;
import org.bouncycastle.its.operator.ETSIDataEncryptor;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;

public class ETSIEncryptedDataTest
    extends TestCase
{

    public void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }


    public void testDecryption()
        throws Exception
    {


        byte[] item = Hex.decode("03820101826cc2023b5115003e8083996da81b76fbdcaae0289abddfaf2b7198\n" +
            "456dbe5495e58c7c61e32a2c2610ca49a6e39470e44e37f302da99da444426f3\n" +
            "68211d919a06c57b574647b97ccc5180eaf3a6736b866446b150131382011c1e\n" +
            "56af1083537123946957844cc5906698a777dddc317966a3920e16cfad39c697\n" +
            "7f28156bd849b57e33b2a9abd1caa8a08520084214b865a355f6d274c3a64694\n" +
            "b81b605b729c2a6fbe88c561e591a055713698d40cabe196b1c96fefccc05f97\n" +
            "7beef6ce3528950c0e05f1c43749fd06114641c0442d0c952eb2eb0fa6b6f0b3\n" +
            "142c6a7e170c2520edf79076c0b6000d4216af50a72955a28e48b0d5ba14b05e\n" +
            "3ed4e5220c8bcc207070f6738b3b6ecabe056584b971df2a515bccd129bb614d\n" +
            "2666a461542fa4c4d25a67a91bacda14fba0310cb937fa9d5d3351f17272eef2\n" +
            "b6e492c3d7a02df81befed05139ce58a9c7f5d2f24f8acd99c4f8a8adbdd6a53\n" +
            "5f89a8a406430d3a335caa563b35bbb0733379d58f9056d017fdd7");


        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");

        kpGen.initialize(new ECGenParameterSpec("P-256"), new FixedSecureRandom(Hex.decode("06EB0D8314ADC4C3564A8E721DF1372FF54B5C725D09E2E353F2D0A46003AB86")));

        KeyPair kp = kpGen.generateKeyPair();

        ETSIEncryptedData edc = new ETSIEncryptedData(item);
        ETSIRecipientInfo info = edc.getRecipients().getMatches(new ETSIRecipientID(Hex.decode("6cc2023b5115003e"))).iterator().next();


        ETSIDataDecryptor dec = JcaETSIDataDecryptor.builder(
            kp.getPrivate(),
            Hex.decode("843BA5DC059A5DD3A6BF81842991608C4CB980456B9DA26F6CC2023B5115003E")
        ).provider("BC").build();

        info.getContent(dec); // Will fail on bad tag otherwise

    }

    public void testEncryptionNist()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");

        kpGen.initialize(new ECGenParameterSpec("P-256"), new FixedSecureRandom(Hex.decode("06EB0D8314ADC4C3564A8E721DF1372FF54B5C725D09E2E353F2D0A46003AB86")));

        //  kpGen.initialize(new ECGenParameterSpec("P-256"), new FixedSecureRandom(Hex.decode("06EB0D8314ADC4C3564A8E721DF1372FF54B5C725D09E2E353F2D0A46003AB86")));

        KeyPair kp = kpGen.generateKeyPair();

        ETSIEncryptedDataBuilder builder = new ETSIEncryptedDataBuilder();

        JceETSIKeyWrapper keyWrapper = new JceETSIKeyWrapper.Builder((ECPublicKey)kp.getPublic(), Hex.decode("843BA5DC059A5DD3A6BF81842991608C4CB980456B9DA26F6CC2023B5115003E")).setProvider("BC").build();
        ETSIRecipientInfoBuilder recipientInfoBuilder = new ETSIRecipientInfoBuilder(keyWrapper, Hex.decode("6CC2023B5115003E"));
        builder.addRecipientInfoBuilder(recipientInfoBuilder);

        ETSIDataEncryptor encryptor = new JceETSIDataEncryptor.Builder().setProvider("BC").build();
        ETSIEncryptedData encryptedData = builder.build(encryptor, Strings.toByteArray("Hello World"));

        // recoding

        encryptedData = new ETSIEncryptedData(encryptedData.getEncoded());

        // decryption

        ETSIRecipientInfo info = encryptedData.getRecipients().getMatches(new ETSIRecipientID(Hex.decode("6cc2023b5115003e"))).iterator().next();

        ETSIDataDecryptor dec = JcaETSIDataDecryptor.builder(
            kp.getPrivate(),
            Hex.decode("843BA5DC059A5DD3A6BF81842991608C4CB980456B9DA26F6CC2023B5115003E")
        ).provider("BC").build();

        byte[] content = info.getContent(dec);

        assertEquals("Hello World", Strings.fromByteArray(content));

    }

    public void testEncryptionTele()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");

        kpGen.initialize(new ECGenParameterSpec("brainpoolP256r1"), new FixedSecureRandom(Hex.decode("06EB0D8314ADC4C3564A8E721DF1372FF54B5C725D09E2E353F2D0A46003AB86")));

        //  kpGen.initialize(new ECGenParameterSpec("P-256"), new FixedSecureRandom(Hex.decode("06EB0D8314ADC4C3564A8E721DF1372FF54B5C725D09E2E353F2D0A46003AB86")));

        KeyPair kp = kpGen.generateKeyPair();

        ETSIEncryptedDataBuilder builder = new ETSIEncryptedDataBuilder();

        JceETSIKeyWrapper keyWrapper = new JceETSIKeyWrapper.Builder((ECPublicKey)kp.getPublic(), Hex.decode("843BA5DC059A5DD3A6BF81842991608C4CB980456B9DA26F6CC2023B5115003E")).setProvider("BC").build();
        ETSIRecipientInfoBuilder recipientInfoBuilder = new ETSIRecipientInfoBuilder(keyWrapper, Hex.decode("6CC2023B5115003E"));
        builder.addRecipientInfoBuilder(recipientInfoBuilder);

        ETSIDataEncryptor encryptor = new JceETSIDataEncryptor.Builder().setProvider("BC").build();
        ETSIEncryptedData encryptedData = builder.build(encryptor, Strings.toByteArray("Hello World"));

        // recoding

        encryptedData = new ETSIEncryptedData(encryptedData.getEncoded());

        // decryption

        ETSIRecipientInfo info = encryptedData.getRecipients().getMatches(new ETSIRecipientID(Hex.decode("6cc2023b5115003e"))).iterator().next();

        ETSIDataDecryptor dec = JcaETSIDataDecryptor.builder(
            kp.getPrivate(),
            Hex.decode("843BA5DC059A5DD3A6BF81842991608C4CB980456B9DA26F6CC2023B5115003E")
        ).provider("BC").build();

        byte[] content = info.getContent(dec);

        assertEquals("Hello World", Strings.fromByteArray(content));

    }


    private Object[] getRecipient(String name, String curve)
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");

        kpGen.initialize(new ECGenParameterSpec(curve), new SecureRandom());
        KeyPair kp = kpGen.generateKeyPair();

        //
        // We are using the name recipient hash value and the first 8 bytes are used for the recipient id.
        // This is for the test only.
        //
        byte[] refHash = MessageDigest.getInstance("SHA256").digest(name.getBytes());
        byte[] id = Arrays.copyOfRange(refHash, 0, 8);

        JceETSIKeyWrapper keyWrapper = new JceETSIKeyWrapper.Builder((ECPublicKey)kp.getPublic(), refHash).setProvider("BC").build();
        ETSIRecipientInfoBuilder recipientInfoBuilder = new ETSIRecipientInfoBuilder(keyWrapper, id);

        // We need the private key for the test.
        return new Object[]{recipientInfoBuilder, kp.getPrivate(), refHash, id};

    }


    public void testEncryptionMulti()
        throws Exception
    {

        Object[][] items = new Object[][]{
            getRecipient("RCP1", "P-256"),
            getRecipient("RCP2", "brainpoolP256r1"),
        };


        ETSIEncryptedDataBuilder builder = new ETSIEncryptedDataBuilder();

        builder.addRecipientInfoBuilder((ETSIRecipientInfoBuilder)items[0][0]);
        builder.addRecipientInfoBuilder((ETSIRecipientInfoBuilder)items[1][0]);

        ETSIDataEncryptor encryptor = new JceETSIDataEncryptor.Builder().setProvider("BC").build();
        ETSIEncryptedData encryptedData = builder.build(encryptor, Strings.toByteArray("Test message"));

        // recoding
        encryptedData = new ETSIEncryptedData(encryptedData.getEncoded());

        // Find and decrypt for each recipient.
        for (Object[] item : items)
        {
            ETSIRecipientInfo info = encryptedData.getRecipients().getMatches(new ETSIRecipientID((byte[])item[3])).iterator().next();

            ETSIDataDecryptor dec = JcaETSIDataDecryptor.builder(
                (PrivateKey)item[1],
                (byte[])item[2]
            ).provider("BC").build();

            byte[] content = info.getContent(dec);

            assertEquals("Test message", Strings.fromByteArray(content));
        }
    }


}
