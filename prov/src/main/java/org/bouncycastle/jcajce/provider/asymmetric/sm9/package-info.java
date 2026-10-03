/**
 * JCA/JCE provider classes for the SM9 identity-based cryptographic algorithms (GM/T 0044-2016),
 * registered in the BouncyCastle provider: the master key-pair generators, the key factory,
 * {@code Signature.SM9}, {@code Cipher.SM9}, {@code KeyAgreement.SM9} and the SM9 KEM through
 * {@code KeyGenerator.SM9-KEM} (and {@code KEM.SM9-KEM} on Java 21 and later). The public key
 * interfaces these classes implement are in {@link org.bouncycastle.jcajce.interfaces}; the
 * lightweight implementation they wrap is described in {@link org.bouncycastle.math.ec.sm9}.
 * <p>
 * <b>Serialization.</b> Only the master keys are serializable. Each is written as an
 * {@code SM9KeyProxy} holding its standard encoding, and rebuilt through the key factory by the
 * proxy's {@code readResolve}; the user keys and the key exchange's ephemeral keys refuse to be
 * written, and no key class accepts a stream that names it directly. A deserialization filter
 * ({@code java.io.ObjectInputFilter}) is also shown the object {@code readResolve} returns, so an
 * allow-list for SM9 master keys has to name the resolved class as well as the proxy and the byte
 * array it carries, for example:
 * <pre>
 * org.bouncycastle.jcajce.provider.asymmetric.sm9.SM9KeyProxy;
 * org.bouncycastle.jcajce.provider.asymmetric.sm9.BCSM9SigMasterPublicKey;
 * org.bouncycastle.jcajce.provider.asymmetric.sm9.BCSM9SigMasterPrivateKey;
 * org.bouncycastle.jcajce.provider.asymmetric.sm9.BCSM9EncMasterPublicKey;
 * org.bouncycastle.jcajce.provider.asymmetric.sm9.BCSM9EncMasterPrivateKey;
 * [B;!*
 * </pre>
 * (as one pattern string, without the line breaks). A filter naming the proxy alone rejects every
 * SM9 key. Serialization carries no integrity protection: a stream yields whatever well-formed
 * master key it encodes, so a stored key that must not be substituted or corrupted needs protecting
 * by the application.
 */
package org.bouncycastle.jcajce.provider.asymmetric.sm9;
