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
    short cipher_suite;
    List<EncryptedGroupSecrets> secrets;
    byte[] encrypted_group_info;

    public int find(CipherSuite suite, KeyPackage kp) throws IOException
    {

        byte[] ref = suite.refHash(MLSOutputStream.encode(kp),"MLS 1.0 KeyPackage Reference");

        for (int i = 0; i < secrets.size(); i++)
        {
            if(Arrays.equals(ref, secrets.get(i).new_member))
            {
                return i;
            }
        }
        return -1;
    }

    public GroupInfo decrypt(CipherSuite suite, byte[] joinerSecret, List<KeyScheduleEpoch.PSKWithSecret> psks) throws IOException, InvalidCipherTextException
    {
        KeyGeneration keyAndNonce = getGroupInforKeyNonce(suite, joinerSecret, psks);
        byte[] groupInfoData = suite.getAEAD().open(
                keyAndNonce.key,
                keyAndNonce.nonce,
                null,
                encrypted_group_info);
        return (GroupInfo) MLSInputStream.decode(groupInfoData, GroupInfo.class);
    }

    private KeyGeneration getGroupInforKeyNonce(CipherSuite suite, byte[] joinerSecret, List<KeyScheduleEpoch.PSKWithSecret> psks) throws IOException
    {
        Secret welcomeSecret = KeyScheduleEpoch.welcomeSecret(suite, joinerSecret, psks);
        Secret key = welcomeSecret.expandWithLabel(suite, "key", new byte[0], suite.getAEAD().getKeySize());
        Secret nonce = welcomeSecret.expandWithLabel(suite, "nonce", new byte[0], suite.getAEAD().getNonceSize());
        return new KeyGeneration(-1, key, nonce);
    }

    public GroupSecrets decryptSecrets(CipherSuite suite, int kpIndex, byte[] initPrivKey) throws InvalidCipherTextException, IOException
    {
        HPKECiphertext ct = secrets.get(kpIndex).encrypted_group_secrets;
        byte[] secretsData = suite.decryptWithLabel(initPrivKey, "Welcome", encrypted_group_info, ct.kem_output, ct.ciphertext);
        return (GroupSecrets) MLSInputStream.decode(secretsData, GroupSecrets.class);
    }


    Welcome(MLSInputStream stream) throws IOException
    {
        cipher_suite = (short) stream.read(short.class);
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
