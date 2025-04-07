package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.bcpg.sig.PreferredAEADCiphersuites;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;

public abstract class AbstractOpenPGPKeySignatureGenerator
{

    /**
     * Standard AEAD encryption preferences (SEIPDv2).
     * By default, only announce support for OCB + AES.
     */
    protected SignatureSubpacketsFunction defaultAeadAlgorithmPreferences = new SignatureSubpacketsFunction()
    {
        public PGPSignatureSubpacketGenerator apply(PGPSignatureSubpacketGenerator subpackets)
        {
            subpackets.removePacketsOfType(SignatureSubpacketTags.PREFERRED_AEAD_ALGORITHMS);
            subpackets.setPreferredAEADCiphersuites(PreferredAEADCiphersuites.builder(false)
                    .addCombination(SymmetricKeyAlgorithmTags.AES_256, AEADAlgorithmTags.OCB)
                    .addCombination(SymmetricKeyAlgorithmTags.AES_192, AEADAlgorithmTags.OCB)
                    .addCombination(SymmetricKeyAlgorithmTags.AES_128, AEADAlgorithmTags.OCB));
            return subpackets;
        }
    };

    /**
     * Standard symmetric-key encryption preferences (SEIPDv1).
     * By default, announce support for AES.
     */
    protected SignatureSubpacketsFunction defaultSymmetricKeyPreferences = new SignatureSubpacketsFunction()
    {
        public PGPSignatureSubpacketGenerator apply(PGPSignatureSubpacketGenerator subpackets)
        {
            subpackets.removePacketsOfType(SignatureSubpacketTags.PREFERRED_SYM_ALGS);
            subpackets.setPreferredSymmetricAlgorithms(false, new int[]{
                    SymmetricKeyAlgorithmTags.AES_256, SymmetricKeyAlgorithmTags.AES_192, SymmetricKeyAlgorithmTags.AES_128
            });
            return subpackets;
        }
    };

    /**
     * Standard signature hash algorithm preferences.
     * By default, only announce SHA3 and SHA2 algorithms.
     */
    protected SignatureSubpacketsFunction defaultHashAlgorithmPreferences = new SignatureSubpacketsFunction()
    {
        public PGPSignatureSubpacketGenerator apply(PGPSignatureSubpacketGenerator subpackets)
        {
            subpackets.removePacketsOfType(SignatureSubpacketTags.PREFERRED_HASH_ALGS);
            subpackets.setPreferredHashAlgorithms(false, new int[]{
                    HashAlgorithmTags.SHA3_512, HashAlgorithmTags.SHA3_256,
                    HashAlgorithmTags.SHA512, HashAlgorithmTags.SHA384, HashAlgorithmTags.SHA256
            });
            return subpackets;
        }
    };

    /**
     * Standard compression algorithm preferences.
     * By default, announce support for all known algorithms.
     */
    protected SignatureSubpacketsFunction defaultCompressionAlgorithmPreferences = new SignatureSubpacketsFunction()
    {
        public PGPSignatureSubpacketGenerator apply(PGPSignatureSubpacketGenerator subpackets)
        {
            subpackets.removePacketsOfType(SignatureSubpacketTags.PREFERRED_COMP_ALGS);
            subpackets.setPreferredCompressionAlgorithms(false, new int[]{
                    CompressionAlgorithmTags.UNCOMPRESSED, CompressionAlgorithmTags.ZIP,
                    CompressionAlgorithmTags.ZLIB, CompressionAlgorithmTags.BZIP2
            });
            return subpackets;
        }
    };

    /**
     * Standard features to announce.
     * By default, announce SEIPDv1 (modification detection) and SEIPDv2.
     */
    protected SignatureSubpacketsFunction defaultFeatures = new SignatureSubpacketsFunction()
    {
        public PGPSignatureSubpacketGenerator apply(PGPSignatureSubpacketGenerator subpackets)
        {
            subpackets.removePacketsOfType(SignatureSubpacketTags.FEATURES);
            subpackets.setFeature(false, (byte)(Features.FEATURE_MODIFICATION_DETECTION | Features.FEATURE_SEIPD_V2));
            return subpackets;
        }
    };

    /**
     * Standard signature subpackets for signing subkey's binding signatures.
     * Sets the keyflag subpacket to SIGN_DATA.
     */
    protected SignatureSubpacketsFunction signingSubkeySubpackets = new SignatureSubpacketsFunction()
    {
        public PGPSignatureSubpacketGenerator apply(PGPSignatureSubpacketGenerator subpackets)
        {
            subpackets.removePacketsOfType(SignatureSubpacketTags.KEY_FLAGS);
            subpackets.setKeyFlags(true, KeyFlags.SIGN_DATA);
            return subpackets;
        }
    };

    /**
     * Standard signature subpackets for encryption subkey's binding signatures.
     * Sets the keyflag subpacket to ENCRYPT_STORAGE|ENCRYPT_COMMS.
     */
    protected SignatureSubpacketsFunction encryptionSubkeySubpackets = new SignatureSubpacketsFunction()
    {
        public PGPSignatureSubpacketGenerator apply(PGPSignatureSubpacketGenerator subpackets)
        {
            subpackets.removePacketsOfType(SignatureSubpacketTags.KEY_FLAGS);
            subpackets.setKeyFlags(true, KeyFlags.ENCRYPT_STORAGE | KeyFlags.ENCRYPT_COMMS);
            return subpackets;
        }
    };

    /**
     * Standard signature subpackets for the direct-key signature.
     * Sets default features, hash-, compression-, symmetric-key-, and AEAD algorithm preferences.
     */
    protected SignatureSubpacketsFunction directKeySignatureSubpackets = new SignatureSubpacketsFunction()
    {
        public PGPSignatureSubpacketGenerator apply(PGPSignatureSubpacketGenerator subpackets)
        {
            subpackets = defaultFeatures.apply(subpackets);
            subpackets = defaultHashAlgorithmPreferences.apply(subpackets);
            subpackets = defaultCompressionAlgorithmPreferences.apply(subpackets);
            subpackets = defaultSymmetricKeyPreferences.apply(subpackets);
            subpackets = defaultAeadAlgorithmPreferences.apply(subpackets);
            return subpackets;
        }
    };

    public void setDefaultAeadAlgorithmPreferences(SignatureSubpacketsFunction aeadAlgorithmPreferences)
    {
        this.defaultAeadAlgorithmPreferences = aeadAlgorithmPreferences;
    }

    public void setDefaultSymmetricKeyPreferences(SignatureSubpacketsFunction symmetricKeyPreferences)
    {
        this.defaultSymmetricKeyPreferences = symmetricKeyPreferences;
    }

    public void setDefaultHashAlgorithmPreferences(SignatureSubpacketsFunction hashAlgorithmPreferences)
    {
        this.defaultHashAlgorithmPreferences = hashAlgorithmPreferences;
    }

    public void setDefaultCompressionAlgorithmPreferences(SignatureSubpacketsFunction compressionAlgorithmPreferences)
    {
        this.defaultCompressionAlgorithmPreferences = compressionAlgorithmPreferences;
    }

    public void setDirectKeySignatureSubpackets(SignatureSubpacketsFunction directKeySignatureSubpackets)
    {
        this.directKeySignatureSubpackets = directKeySignatureSubpackets;
    }

    public void setDefaultFeatures(SignatureSubpacketsFunction features)
    {
        this.defaultFeatures = features;
    }

    public void setSigningSubkeySubpackets(SignatureSubpacketsFunction signingSubkeySubpackets)
    {
        this.signingSubkeySubpackets = signingSubkeySubpackets;
    }

    public void setEncryptionSubkeySubpackets(SignatureSubpacketsFunction encryptionSubkeySubpackets)
    {
        this.encryptionSubkeySubpackets = encryptionSubkeySubpackets;
    }
}
