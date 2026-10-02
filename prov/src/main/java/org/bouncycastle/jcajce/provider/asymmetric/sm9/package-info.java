/**
 * JCA/JCE provider classes for the SM9 identity-based cryptographic algorithms (GM/T 0044-2016),
 * registered in the BouncyCastle provider: the master key-pair generators, the key factory,
 * {@code Signature.SM9}, {@code Cipher.SM9}, {@code KeyAgreement.SM9} and the SM9 KEM through
 * {@code KeyGenerator.SM9-KEM} (and {@code KEM.SM9-KEM} on Java 21 and later). The public key
 * interfaces these classes implement are in {@link org.bouncycastle.jcajce.interfaces}; the
 * lightweight implementation they wrap is described in {@link org.bouncycastle.math.ec.sm9}.
 */
package org.bouncycastle.jcajce.provider.asymmetric.sm9;
