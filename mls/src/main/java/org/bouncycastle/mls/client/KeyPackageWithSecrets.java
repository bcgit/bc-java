package org.bouncycastle.mls.client;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.mls.codec.KeyPackage;

public class KeyPackageWithSecrets {
    public AsymmetricCipherKeyPair initKeyPair; // HPKE key pair
    public AsymmetricCipherKeyPair encryptionKeyPair; // HPKE key pair
    public AsymmetricCipherKeyPair signatureKeyPair; // sig key pair
    public KeyPackage keyPackage;

    public KeyPackageWithSecrets(AsymmetricCipherKeyPair initKeyPair, AsymmetricCipherKeyPair encryptionKeyPair, AsymmetricCipherKeyPair signatureKeyPair, KeyPackage keyPackage)
    {
        this.initKeyPair = initKeyPair;
        this.encryptionKeyPair = encryptionKeyPair;
        this.signatureKeyPair = signatureKeyPair;
        this.keyPackage = keyPackage;
    }
}