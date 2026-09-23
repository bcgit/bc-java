/**
 * JCA/JCE provider classes for Leighton-Micali Signatures and the Hierarchical Signature System
 * built on them (RFC 8554, profiled by NIST SP 800-208), registered in the BouncyCastle provider as
 * the KeyFactory, KeyPairGenerator and Signature services named "LMS", each also aliased to the
 * PKCS id-alg-hss-lms-hashsig object identifier. They replace the deprecated classes in
 * org.bouncycastle.pqc.jcajce.provider.lms, whose interfaces they still implement.
 */
package org.bouncycastle.jcajce.provider.asymmetric.lms;
