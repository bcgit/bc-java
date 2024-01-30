package org.bouncycastle.mls.test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.hpke.HPKE;
import org.bouncycastle.mls.GroupKeySet;
import org.bouncycastle.mls.TreeKEM.LeafIndex;
import org.bouncycastle.mls.TreeSize;
import org.bouncycastle.mls.codec.AuthenticatedContent;
import org.bouncycastle.mls.codec.ContentType;
import org.bouncycastle.mls.codec.Extension;
import org.bouncycastle.mls.codec.FramedContent;
import org.bouncycastle.mls.codec.GroupContext;
import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSMessage;
import org.bouncycastle.mls.codec.MLSOutputStream;
import org.bouncycastle.mls.codec.PrivateMessage;
import org.bouncycastle.mls.codec.PublicMessage;
import org.bouncycastle.mls.codec.Sender;
import org.bouncycastle.mls.codec.WireFormat;
import org.bouncycastle.mls.crypto.MlsCipherSuite;
import org.bouncycastle.mls.crypto.MlsSigner;
import org.bouncycastle.mls.crypto.Secret;
import org.bouncycastle.mls.crypto.bc.BcMlsAead;
import org.bouncycastle.mls.crypto.bc.BcMlsKdf;
import org.bouncycastle.mls.crypto.bc.BcMlsSigner;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import static org.bouncycastle.mls.crypto.MlsCipherSuite.MLS_128_DHKEMP256_AES128GCM_SHA256_P256;
import static org.bouncycastle.mls.crypto.MlsCipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
import static org.bouncycastle.mls.crypto.MlsCipherSuite.MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
import static org.bouncycastle.mls.crypto.MlsCipherSuite.MLS_256_DHKEMP384_AES256GCM_SHA384_P384;
import static org.bouncycastle.mls.crypto.MlsCipherSuite.MLS_256_DHKEMP521_AES256GCM_SHA512_P521;
import static org.bouncycastle.mls.crypto.MlsCipherSuite.MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448;
import static org.bouncycastle.mls.crypto.MlsCipherSuite.MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448;

public class MessageProtectionTest
        extends TestCase
{
    short cipher_suite;
    byte[] group_id;
    long epoch;
    byte[] tree_hash;
    byte[] confirmed_transcript_hash;
    byte[] signature_priv;
    byte[] signature_pub;
    byte[] encryption_secret;
    byte[] sender_data_secret;
    byte[] membership_key;
    byte[] proposal;
    byte[] proposal_priv;
    byte[] proposal_pub;
    byte[] commit;
    byte[] commit_priv;
    byte[] commit_pub;
    byte[] application;
    byte[] application_priv;
    byte[] groupContextBytes;
    GroupContext groupContext;
    MlsCipherSuite suite;


    private void protect(byte[] content, MLSMessage message) throws Exception
    {
        Sender sender = Sender.forMember(new LeafIndex(1));
        byte[] authenticatedData = new byte[0];

        if(message.wireFormat == WireFormat.mls_public_message &&
            message.getContentType() == ContentType.APPLICATION)
        {
            throw new Exception("Unencrypted Application Message");
        }


        FramedContent groupContent = FramedContent.rawContent(
                group_id,
                epoch,
                sender,
                authenticatedData,
                message.getContentType(),
                content
        );

        AuthenticatedContent authContent = AuthenticatedContent.sign(
                message.wireFormat,
                groupContent,
                suite,
                signature_priv,
                groupContextBytes
        );
        if (groupContent.getContentType() == ContentType.COMMIT)
        {
            //TODO: figure out what to put as the confirmation tag
            Secret secret = new Secret(new byte[0]);
            Secret tag = secret.deriveSecret(suite, "confirmation_tag");
            authContent.setConfirmationTag(tag.value());
        }
        switch (message.wireFormat)
        {
            case mls_public_message:
                message.publicMessage = PublicMessage.protect(authContent, suite, membership_key, groupContextBytes);
                break;
            case mls_private_message:
                GroupKeySet keys = getKeys();
                // TODO: get padding size
                message.privateMessage = PrivateMessage.protect(authContent, suite, keys, sender_data_secret, 0);
                break;
            case mls_welcome:
                break;
            case mls_group_info:
                break;
            case mls_key_package:
                break;
        }


    }
    private FramedContent unprotect(MLSMessage message) throws Exception
    {
        AuthenticatedContent auth;
        switch (message.wireFormat)
        {
            case mls_public_message:
                auth = message.publicMessage.unprotect(suite, new Secret(membership_key), groupContext);
                break;
            case mls_private_message:
                GroupKeySet keys = getKeys();
                auth = message.privateMessage.unprotect(suite, keys, sender_data_secret);
                break;
            default:
                return null;
        }

        boolean verified = auth.verify(suite, signature_pub, groupContextBytes);
        assertTrue(verified);

        return auth.getContent();
    }
    private GroupKeySet getKeys() throws IOException, IllegalAccessException
    {
        TreeSize treeSize = TreeSize.forLeaves(2);
        Secret encryptedSecret = new Secret(encryption_secret.clone());
        return new GroupKeySet(suite, treeSize, encryptedSecret);
    }

    private MlsCipherSuite createNewSuite(short id)
    {
        switch (id)
        {
            case MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519:
                return new MlsCipherSuite(MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519, new BcMlsSigner(MlsSigner.ed25519), new BcMlsKdf(new SHA256Digest()), new BcMlsAead(HPKE.aead_AES_GCM128), new HPKE(HPKE.mode_base, HPKE.kem_X25519_SHA256, HPKE.kdf_HKDF_SHA256, HPKE.aead_AES_GCM128));

            case MLS_128_DHKEMP256_AES128GCM_SHA256_P256:
                return new MlsCipherSuite(MLS_128_DHKEMP256_AES128GCM_SHA256_P256, new BcMlsSigner(MlsSigner.ecdsa_secp256r1_sha256), new BcMlsKdf(new SHA256Digest()), new BcMlsAead(HPKE.aead_AES_GCM128), new HPKE(HPKE.mode_base, HPKE.kem_P256_SHA256, HPKE.kdf_HKDF_SHA256, HPKE.aead_AES_GCM128));

            case MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519:
                return new MlsCipherSuite(MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519, new BcMlsSigner(MlsSigner.ed25519), new BcMlsKdf(new SHA256Digest()), new BcMlsAead(HPKE.aead_CHACHA20_POLY1305), new HPKE(HPKE.mode_base, HPKE.kem_X25519_SHA256, HPKE.kdf_HKDF_SHA256, HPKE.aead_CHACHA20_POLY1305));

            case MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448:
                return new MlsCipherSuite(MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448, new BcMlsSigner(MlsSigner.ed448), new BcMlsKdf(new SHA512Digest()), new BcMlsAead(HPKE.aead_AES_GCM256), new HPKE(HPKE.mode_base, HPKE.kem_X448_SHA512, HPKE.kdf_HKDF_SHA512, HPKE.aead_AES_GCM256));

            case MLS_256_DHKEMP521_AES256GCM_SHA512_P521:
                return new MlsCipherSuite(MLS_256_DHKEMP521_AES256GCM_SHA512_P521, new BcMlsSigner(MlsSigner.ecdsa_secp521r1_sha512), new BcMlsKdf(new SHA512Digest()), new BcMlsAead(HPKE.aead_AES_GCM256), new HPKE(HPKE.mode_base, HPKE.kem_P521_SHA512, HPKE.kdf_HKDF_SHA512, HPKE.aead_AES_GCM256));

            case MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448:
                return new MlsCipherSuite(MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448, new BcMlsSigner(MlsSigner.ed448), new BcMlsKdf(new SHA512Digest()), new BcMlsAead(HPKE.aead_CHACHA20_POLY1305), new HPKE(HPKE.mode_base, HPKE.kem_X448_SHA512, HPKE.kdf_HKDF_SHA512, HPKE.aead_CHACHA20_POLY1305));

            case MLS_256_DHKEMP384_AES256GCM_SHA384_P384:
                return new MlsCipherSuite(MLS_256_DHKEMP384_AES256GCM_SHA384_P384, new BcMlsSigner(MlsSigner.ecdsa_secp384r1_sha384), new BcMlsKdf(new SHA384Digest()), new BcMlsAead(HPKE.aead_AES_GCM256), new HPKE(HPKE.mode_base, HPKE.kem_P384_SHA348, HPKE.kdf_HKDF_SHA384, HPKE.aead_AES_GCM256));

        }
        return null;
    }



    public void testMessageProtection()
            throws Exception
    {
        InputStream src = TestResourceFinder.findTestResource("mls/testVectors/", "message-protection.txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line;
        HashMap<String, String> buf = new HashMap<String, String>();
        int count = 0;

        while((line = bin.readLine())!= null)
        {
            line = line.trim();
            if (line.length() == 0)
            {
                if (buf.size() > 0)
                {
                    System.out.println("test case: " + count);
                    cipher_suite = Short.parseShort(buf.get("cipher_suite"));
                    group_id = Hex.decode(buf.get("group_id"));
                    epoch = Long.parseLong(buf.get("epoch"));
                    tree_hash = Hex.decode(buf.get("tree_hash"));
                    confirmed_transcript_hash = Hex.decode(buf.get("confirmed_transcript_hash"));
                    signature_priv = Hex.decode(buf.get("signature_priv"));
                    signature_pub = Hex.decode(buf.get("signature_pub"));
                    encryption_secret = Hex.decode(buf.get("encryption_secret"));
                    sender_data_secret = Hex.decode(buf.get("sender_data_secret"));
                    membership_key = Hex.decode(buf.get("membership_key"));
                    proposal = Hex.decode(buf.get("proposal"));
                    proposal_priv = Hex.decode(buf.get("proposal_priv"));
                    proposal_pub = Hex.decode(buf.get("proposal_pub"));
                    commit = Hex.decode(buf.get("commit"));
                    commit_priv = Hex.decode(buf.get("commit_priv"));
                    commit_pub = Hex.decode(buf.get("commit_pub"));
                    application = Hex.decode(buf.get("application"));
                    application_priv = Hex.decode(buf.get("application_priv"));

                    suite = createNewSuite(cipher_suite);

                    AsymmetricCipherKeyPair sigKeyPair = suite.deserializeSignaturePrivateKey(signature_priv);
                    byte[] sigPubBytes = suite.serializeSignaturePublicKey(sigKeyPair.getPublic());

                    // Sanity Check
                    assertTrue(Arrays.areEqual(signature_pub, sigPubBytes));

                    // Construct a GroupContext object with the provided cipher_suite, group_id, epoch, tree_hash,
                    // and confirmed_transcript_hash values, and empty extensions
                    groupContext = new GroupContext(
                            suite,
                            group_id,
                            epoch,
                            tree_hash,
                            confirmed_transcript_hash,
                            new ArrayList<Extension>()
                    );
                    groupContextBytes = MLSOutputStream.encode(groupContext);

                    // Proposal

                    // verify proposal unprotect public message
                    MLSMessage proposalPub = (MLSMessage) MLSInputStream.decode(proposal_pub, MLSMessage.class);
                    FramedContent proposalPubUnprotected =  unprotect(proposalPub);
                    assertTrue(Arrays.areEqual(proposalPubUnprotected.getContentBytes(), proposal));

                    // verify proposal unprotect private message
                    MLSMessage proposalPriv = (MLSMessage) MLSInputStream.decode(proposal_priv, MLSMessage.class);
                    FramedContent proposalPrivUnprotected = unprotect(proposalPriv);
                    assertTrue(Arrays.areEqual(proposalPrivUnprotected.getContentBytes(), proposal));

                    // Commit

                    // verify commit unprotect public message
                    MLSMessage commitPub = (MLSMessage) MLSInputStream.decode(commit_pub, MLSMessage.class);
                    FramedContent commitPubUnprotected = unprotect(commitPub);
                    assertTrue(Arrays.areEqual(commitPubUnprotected.getContentBytes(), commit));

                    // verify commit unprotect private message
                    MLSMessage commitPriv = (MLSMessage) MLSInputStream.decode(commit_priv, MLSMessage.class);
                    FramedContent commitPrivUnprotected = unprotect(commitPriv);
                    assertTrue(Arrays.areEqual(commitPrivUnprotected.getContentBytes(), commit));

                    // Application

                    // verify application unprotect private message
                    MLSMessage appPriv = (MLSMessage) MLSInputStream.decode(application_priv, MLSMessage.class);
                    FramedContent appPrivUnprotected = unprotect(appPriv);
                    assertTrue(Arrays.areEqual(appPrivUnprotected.getContentBytes(), application));

                    // Verify protect/unprotect rounds trips
                    // Todo: make a different object
                    protect(proposal, proposalPub); // proposalPub = proposalPubProtected
                    FramedContent proposalPubProtectedUnprotected = unprotect(proposalPub);
                    assertTrue(Arrays.areEqual(proposalPubProtectedUnprotected.getContentBytes(), proposal));

                    protect(proposal, proposalPriv); // proposalPriv = proposalPrivProtected
                    FramedContent proposalPrivProtectedUnprotected = unprotect(proposalPriv);
                    assertTrue(Arrays.areEqual(proposalPrivProtectedUnprotected.getContentBytes(), proposal));

                    protect(commit, commitPub); // commitPub = commitPubProtected
                    FramedContent commitPubProtectedUnprotected = unprotect(commitPub);
                    assertTrue(Arrays.areEqual(commitPubProtectedUnprotected.getContentBytes(), commit));

                    suite = createNewSuite(cipher_suite); // reset AEAD
                    protect(commit, commitPriv); // commitPriv = commitPrivProtected
                    FramedContent commitPrivProtectedUnprotected = unprotect(commitPriv);
                    assertTrue(Arrays.areEqual(commitPrivProtectedUnprotected.getContentBytes(), commit));

                    protect(application, appPriv); // appPriv = appPrivProtected
                    FramedContent appPrivProtectedUnprotected = unprotect(appPriv);
                    assertTrue(Arrays.areEqual(appPrivProtectedUnprotected.getContentBytes(), application));

                    // verify that protecting a public message fails

                    count++;
                }
            }
            int a = line.indexOf("=");
            if (a > -1)
            {
                buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
        }
    }

}
