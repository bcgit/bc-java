/**
 * Crypto-services-constraint framework: lets callers limit which cryptographic
 * primitives the lightweight API will produce (by key size, by allowlist, by purpose, or - for
 * the quantum-vulnerable public-key algorithms - by the NIST IR 8547 transition timetable).
 * Plugs into {@link org.bouncycastle.crypto.CryptoServicesRegistrar}. The post-quantum
 * algorithms report to the framework with the classical security strength NIST assigns to
 * their parameter set, so a {@link org.bouncycastle.crypto.constraints.BitsOfSecurityConstraint}
 * of 192 refuses ML-KEM-512, ML-DSA-44 and the 128-bit SLH-DSA sets as it does a 2048-bit RSA key.
 */
package org.bouncycastle.crypto.constraints;
