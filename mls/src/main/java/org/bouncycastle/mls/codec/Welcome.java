package org.bouncycastle.mls.codec;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.mls.KeyGeneration;
import org.bouncycastle.mls.KeyScheduleEpoch;
import org.bouncycastle.mls.crypto.CipherSuite;
import org.bouncycastle.mls.crypto.Secret;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Welcome
        implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    public short cipher_suite;

    CipherSuite suite;
    List<EncryptedGroupSecrets> secrets;
    byte[] encrypted_group_info;

    //
    private Secret joinerSecret;
    private List<PreSharedKeyID> psks;
    //TODO DELETE TEST
//    public static ArrayList<byte[]> TESTWELCOME = new ArrayList<>(java.util.Arrays.asList(
//            Hex.decode("6dc8e6518f07a8ff73c37006264393e780ad3bae0271adad4e7afeaca9d0d87b"),
//            Hex.decode("6b512c0c59ec6b3f4d03608de8f93b08c7afe4cbe95e989e4d81cc81379e34bd2eadbc0cd4f7ef5d38e9e76f8a0666d18803d4")
//    ));

    public Welcome(CipherSuite suite, byte[] joinerSecret, List<KeyScheduleEpoch.PSKWithSecret> psks, byte[] groupInfo) throws IOException, InvalidCipherTextException
    {
        this.cipher_suite = suite.getSuiteId();
        this.suite = suite;
        this.joinerSecret = new Secret(joinerSecret);
        // Cache the list of PSK IDs
        this.psks = new ArrayList<>();
        for (KeyScheduleEpoch.PSKWithSecret psk : psks)
        {
            this.psks.add(psk.id);
        }

        // Pre-encrypt the GroupInfo
        KeyGeneration keyGen = getGroupInfoKeyNonce(joinerSecret, psks);
        this.encrypted_group_info = suite.getAEAD().seal(
                keyGen.key,
                keyGen.nonce,
                new byte[0], //TODO Check if aad is needed!
                groupInfo
        );

        this.secrets = new ArrayList<>();
    }

    public int find(KeyPackage kp) throws IOException
    {

        byte[] ref = suite.refHash(MLSOutputStream.encode(kp),"MLS 1.0 KeyPackage Reference");
//        System.out.println("keypackage ref: " +Hex.toHexString(ref));
        for (int i = 0; i < secrets.size(); i++)
        {
//            System.out.println("secrets[" + i + "]: " +Hex.toHexString(secrets.get(i).new_member));
            if(Arrays.equals(ref, secrets.get(i).new_member))
            {
                return i;
            }
        }
        return -1;
    }

    public void encrypt(KeyPackage kp, Secret pathSecret) throws IOException, InvalidCipherTextException
    {

        GroupSecrets gs = new GroupSecrets(joinerSecret.value(), null, psks);
        if (pathSecret != null)
        {
            gs.path_secret = new PathSecret(pathSecret.value());
        }
        byte[] gsBytes = MLSOutputStream.encode(gs);
        //todo: get rid of new suite
        CipherSuite suite = new CipherSuite(kp.cipher_suite);
        byte[][] ctAndEnc = suite.encryptWithLabel(kp.init_key, "Welcome", encrypted_group_info, gsBytes);
        //TODO DELETE TEST
//        ctAndEnc[1] = TESTWELCOME.get(0); TESTWELCOME.remove(0);
//        ctAndEnc[0] = TESTWELCOME.get(0); TESTWELCOME.remove(0);
        secrets.add(
                new EncryptedGroupSecrets(
                    suite.refHash(MLSOutputStream.encode(kp),"MLS 1.0 KeyPackage Reference"),
                    new HPKECiphertext(ctAndEnc[1], ctAndEnc[0])
                )
        );
    }

    public GroupInfo decrypt(byte[] joinerSecret, List<KeyScheduleEpoch.PSKWithSecret> psks) throws IOException, InvalidCipherTextException
    {
        KeyGeneration keyAndNonce = getGroupInfoKeyNonce(joinerSecret, psks);
        byte[] groupInfoData = suite.getAEAD().open(
                keyAndNonce.key,
                keyAndNonce.nonce,
                new byte[0],
                encrypted_group_info);
        return (GroupInfo) MLSInputStream.decode(groupInfoData, GroupInfo.class);
    }

    private KeyGeneration getGroupInfoKeyNonce(byte[] joinerSecret, List<KeyScheduleEpoch.PSKWithSecret> psks) throws IOException
    {
        Secret welcomeSecret = KeyScheduleEpoch.welcomeSecret(suite, joinerSecret, psks);
        Secret key = welcomeSecret.expandWithLabel(suite, "key", new byte[0], suite.getAEAD().getKeySize());
        Secret nonce = welcomeSecret.expandWithLabel(suite, "nonce", new byte[0], suite.getAEAD().getNonceSize());
        return new KeyGeneration(-1, key, nonce);
    }

    public GroupSecrets decryptSecrets(int kpIndex, byte[] initPrivKey) throws InvalidCipherTextException, IOException
    {
        HPKECiphertext ct = secrets.get(kpIndex).encrypted_group_secrets;
        byte[] secretsData = suite.decryptWithLabel(initPrivKey, "Welcome", encrypted_group_info, ct.kem_output, ct.ciphertext);
        return (GroupSecrets) MLSInputStream.decode(secretsData, GroupSecrets.class);
    }


    Welcome(MLSInputStream stream) throws IOException
    {
        cipher_suite = (short) stream.read(short.class);
        suite = new CipherSuite(cipher_suite);
        secrets = new ArrayList<>();
        stream.readList(secrets, EncryptedGroupSecrets.class);
        encrypted_group_info = stream.readOpaque();
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException
    {
        stream.write(cipher_suite);
        stream.writeList(secrets);
        stream.writeOpaque(encrypted_group_info);
    }
}
