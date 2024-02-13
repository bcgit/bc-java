package org.bouncycastle.mls.codec;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.mls.KeyGeneration;
import org.bouncycastle.mls.KeyScheduleEpoch;
import org.bouncycastle.mls.crypto.MlsCipherSuite;
import org.bouncycastle.mls.crypto.Secret;

public class Welcome
    implements MLSInputStream.Readable, MLSOutputStream.Writable
{
    short cipher_suite;

    MlsCipherSuite suite;
    List<EncryptedGroupSecrets> secrets;
    byte[] encrypted_group_info;

    //
    private Secret joinerSecret;
    private List<PreSharedKeyID> psks;

    public MlsCipherSuite getSuite()
    {
        return suite;
    }

    public Welcome(MlsCipherSuite suite, byte[] joinerSecret, List<KeyScheduleEpoch.PSKWithSecret> psks, byte[] groupInfo)
        throws IOException, InvalidCipherTextException
    {
        this.cipher_suite = suite.getSuiteID();
        this.suite = suite;
        this.joinerSecret = new Secret(joinerSecret);
        // Cache the list of PSK IDs
        this.psks = new ArrayList<PreSharedKeyID>();
        for (KeyScheduleEpoch.PSKWithSecret psk : psks)
        {
            this.psks.add(psk.id);
        }

        // Pre-encrypt the GroupInfo
        KeyGeneration keyGen = getGroupInfoKeyNonce(joinerSecret, psks);
        this.encrypted_group_info = suite.getAEAD().seal(
            keyGen.key,
            keyGen.nonce,
            new byte[0],
            groupInfo
        );

        this.secrets = new ArrayList<EncryptedGroupSecrets>();
    }

    public int find(KeyPackage kp)
        throws IOException
    {

        byte[] ref = suite.refHash(MLSOutputStream.encode(kp), "MLS 1.0 KeyPackage Reference");
        for (int i = 0; i < secrets.size(); i++)
        {
            if (Arrays.equals(ref, secrets.get(i).new_member))
            {
                return i;
            }
        }
        return -1;
    }

    public void encrypt(KeyPackage kp, Secret pathSecret)
        throws IOException, InvalidCipherTextException
    {

        GroupSecrets gs = new GroupSecrets(joinerSecret.value(), null, psks);
        if (pathSecret != null)
        {
            gs.path_secret = new PathSecret(pathSecret.value());
        }
        byte[] gsBytes = MLSOutputStream.encode(gs);
        MlsCipherSuite suite = kp.suite;
        byte[][] ctAndEnc = suite.encryptWithLabel(kp.init_key, "Welcome", encrypted_group_info, gsBytes);
        secrets.add(
            new EncryptedGroupSecrets(
                suite.refHash(MLSOutputStream.encode(kp), "MLS 1.0 KeyPackage Reference"),
                new HPKECiphertext(ctAndEnc[1], ctAndEnc[0])
            )
        );
    }

    public GroupInfo decrypt(byte[] joinerSecret, List<KeyScheduleEpoch.PSKWithSecret> psks)
        throws IOException, InvalidCipherTextException
    {
        KeyGeneration keyAndNonce = getGroupInfoKeyNonce(joinerSecret, psks);
        byte[] groupInfoData = suite.getAEAD().open(
            keyAndNonce.key,
            keyAndNonce.nonce,
            new byte[0],
            encrypted_group_info);
        return (GroupInfo)MLSInputStream.decode(groupInfoData, GroupInfo.class);
    }

    private KeyGeneration getGroupInfoKeyNonce(byte[] joinerSecret, List<KeyScheduleEpoch.PSKWithSecret> psks)
        throws IOException
    {
        Secret welcomeSecret = KeyScheduleEpoch.welcomeSecret(suite, joinerSecret, psks);
        Secret key = welcomeSecret.expandWithLabel(suite, "key", new byte[0], suite.getAEAD().getKeySize());
        Secret nonce = welcomeSecret.expandWithLabel(suite, "nonce", new byte[0], suite.getAEAD().getNonceSize());
        return new KeyGeneration(-1, key, nonce);
    }

    public GroupSecrets decryptSecrets(int kpIndex, byte[] initPrivKey)
        throws InvalidCipherTextException, IOException
    {
        HPKECiphertext ct = secrets.get(kpIndex).encrypted_group_secrets;
        byte[] secretsData = suite.decryptWithLabel(initPrivKey, "Welcome", encrypted_group_info, ct.kem_output, ct.ciphertext);
        return (GroupSecrets)MLSInputStream.decode(secretsData, GroupSecrets.class);
    }

    @SuppressWarnings("unused")
    Welcome(MLSInputStream stream)
        throws Exception
    {
        cipher_suite = (short)stream.read(short.class);
        suite = MlsCipherSuite.getSuite(cipher_suite);
        secrets = new ArrayList<EncryptedGroupSecrets>();
        stream.readList(secrets, EncryptedGroupSecrets.class);
        encrypted_group_info = stream.readOpaque();
    }

    @Override
    public void writeTo(MLSOutputStream stream)
        throws IOException
    {
        stream.write(cipher_suite);
        stream.writeList(secrets);
        stream.writeOpaque(encrypted_group_info);
    }
}
