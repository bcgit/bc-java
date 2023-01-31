package org.bouncycastle.mls;

import org.bouncycastle.mls.crypto.CipherSuite;
import org.bouncycastle.mls.crypto.Secret;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.List;

public class KeyScheduleEpoch {
    public static class PSKWithSecret {
        byte[] id;
        Secret secret;
    }

    public static class JoinSecrets {
        // Cached values
        private final CipherSuite suite;
        // Public values
        public final Secret joinerSecret;
        public final Secret welcomeKey;
        public final Secret welcomeNonce;
        // Carry-forward values
        private final Secret welcomeSecret; // Held to avoid consuming joinerSecret
        private final Secret memberSecret; // Held to derive further secrets

        static Secret pskSecret(CipherSuite suite, List<PSKWithSecret> psks) throws IOException, IllegalAccessException {
            Secret pskSecret = Secret.zero(suite);
            if (psks == null || psks.isEmpty()) {
                return pskSecret;
            }

            for (PSKWithSecret psk : psks) {
                byte[] pskLabel = new byte[0]; // TODO actually encode the PSK label

                Secret pskExtracted = Secret.extract(suite, Secret.zero(suite), psk.secret);
                Secret pskInput = pskExtracted.expandWithLabel(suite, "derived psk", pskLabel, suite.getKDF().getHashLength());
                pskSecret = Secret.extract(suite, pskInput, pskSecret);
            }

            return pskSecret;
        }

        /*
                   init_secret_[n-1]
                         |
                         |
                         V
   commit_secret --> KDF.Extract
                         |
                         |
                         V
                 ExpandWithLabel(., "joiner", GroupContext_[n], KDF.Nh)
                         |
                         |
                         V
                    joiner_secret

    */
        static JoinSecrets forMember(CipherSuite suite, Secret initSecret, Secret commitSecret, List<PSKWithSecret> psks, byte[] context) throws IOException, IllegalAccessException {
            Secret preJoinerSecret = Secret.extract(suite, initSecret, commitSecret);
            Secret joinerSecret = preJoinerSecret.expandWithLabel(suite,"joiner", context, suite.getKDF().getHashLength());
            return new JoinSecrets(suite, joinerSecret, psks);
        }

        /*
                     joiner_secret
                          |
                          |
                          V
psk_secret (or 0) --> KDF.Extract
                          |
                          |
                          +--> DeriveSecret(., "welcome")
                          |    = welcome_secret
                          |
                          V
                  ExpandWithLabel(., "epoch", GroupContext_[n], KDF.Nh)
                          |
                          |
                          V
                     epoch_secret
     */
        public JoinSecrets(CipherSuite suite, Secret joinerSecret, List<PSKWithSecret> psks) throws IOException, IllegalAccessException {
            this.suite = suite;
            this.joinerSecret = joinerSecret;
            this.memberSecret = Secret.extract(suite, joinerSecret, pskSecret(suite, psks));
            this.welcomeSecret = memberSecret.deriveSecret(suite, "welcome");
            this.welcomeKey = welcomeSecret.expand(suite, "key", suite.getAEAD().getKeySize());
            this.welcomeNonce = welcomeSecret.expand(suite, "nonce", suite.getAEAD().getNonceSize());
        }

        public KeyScheduleEpoch complete(TreeSize treeSize, byte[] context) throws IOException, IllegalAccessException {
            Secret epochSecret = memberSecret.expandWithLabel(suite, "epoch", context, suite.getKDF().getHashLength());
            return new KeyScheduleEpoch(suite, treeSize, epochSecret);
        }
    }


    final CipherSuite suite;

    // Secrets derived from the epoch secret
    final Secret initSecret;
    final Secret senderDataSecret;
    final Secret exporterSecret;
    final Secret externalSecret; // TODO derive key pair and discard
    final Secret confirmationKey;
    final Secret membershipKey;
    final Secret resumptionPSK;
    final Secret epochAuthenticator;

    // Further dervied products
    final GroupKeySet groupKeySet;

    public static KeyScheduleEpoch forCreator(CipherSuite suite) throws IOException, IllegalAccessException {
        byte[] epochSecret = new byte[suite.getKDF().getHashLength()];
        SecureRandom rng = new SecureRandom();
        rng.nextBytes(epochSecret);

        TreeSize treeSize = TreeSize.forLeaves(1);
        return new KeyScheduleEpoch(suite, treeSize, new Secret(epochSecret));
    }

    public JoinSecrets startCommit(Secret commitSecret, List<PSKWithSecret> psks, byte[] context) throws IOException, IllegalAccessException {
        return JoinSecrets.forMember(suite, initSecret, commitSecret, psks, context);
    }

    /*
                     epoch_secret
                          |
                          |
                          +--> DeriveSecret(., <label>)
                          |    = <secret>
                          |
                          V
                    DeriveSecret(., "init")
                          |
                          |
                          V
                    init_secret_[n]
     */
    KeyScheduleEpoch(CipherSuite suite, TreeSize treeSize, Secret epochSecret) throws IOException, IllegalAccessException {
        this.suite = suite;
        this.initSecret = epochSecret.deriveSecret(suite, "init");
        this.senderDataSecret = epochSecret.deriveSecret(suite, "sender data");
        this.exporterSecret = epochSecret.deriveSecret(suite, "exporter");
        this.externalSecret = epochSecret.deriveSecret(suite, "external");
        this.confirmationKey = epochSecret.deriveSecret(suite, "confirm");
        this.membershipKey = epochSecret.deriveSecret(suite, "membership");
        this.resumptionPSK = epochSecret.deriveSecret(suite, "resumption");
        this.epochAuthenticator = epochSecret.deriveSecret(suite, "authentication");

        Secret encryptionSecret = epochSecret.deriveSecret(suite, "encryption");
        this.groupKeySet = new GroupKeySet(suite, treeSize, encryptionSecret);
        encryptionSecret.consume();

        epochSecret.consume();
    }

    public KeyScheduleEpoch next(TreeSize treeSize, Secret forceInitSecret, Secret commitSecret, List<PSKWithSecret> psks, byte[] context) throws IOException, IllegalAccessException {
        Secret currInitSecret = initSecret;
        if (forceInitSecret != null) {
            currInitSecret = forceInitSecret;
        }

        JoinSecrets joinSecrets = JoinSecrets.forMember(suite, currInitSecret, commitSecret, psks, context);
        return joinSecrets.complete(treeSize, context);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KeyScheduleEpoch that = (KeyScheduleEpoch) o;
        return suite.equals(that.suite) && initSecret.equals(that.initSecret) && senderDataSecret.equals(that.senderDataSecret) && exporterSecret.equals(that.exporterSecret) && externalSecret.equals(that.externalSecret) && confirmationKey.equals(that.confirmationKey) && membershipKey.equals(that.membershipKey) && resumptionPSK.equals(that.resumptionPSK) && epochAuthenticator.equals(that.epochAuthenticator) && groupKeySet.equals(that.groupKeySet);
    }
}
