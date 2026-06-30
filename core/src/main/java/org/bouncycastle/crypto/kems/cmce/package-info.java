/**
 * The Classic McEliece key encapsulation mechanism as standardised in ISO/IEC 18033-2:2006/Amd
 * 2:2026 (Clause 13): lightweight engine internals for the non-pc and pc ("plaintext confirmation")
 * parameter sets, each in a plain and a semi-systematic ("f") key-generation variant. Driven through
 * the public {@link org.bouncycastle.crypto.generators.CMCEKeyPairGenerator},
 * {@link org.bouncycastle.crypto.kems.CMCEKEMGenerator} and
 * {@link org.bouncycastle.crypto.kems.CMCEKEMExtractor}.
 */
package org.bouncycastle.crypto.kems.cmce;
