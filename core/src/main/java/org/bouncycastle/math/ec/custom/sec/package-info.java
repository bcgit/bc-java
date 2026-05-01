/**
 * Custom implementations of (most of) the curves over Fp from the SEC specification. Uses the new "raw" math classes
 * in place of BigInteger, and includes customized modular reductions taking advantage of the special forms of the primes.
 */
package org.bouncycastle.math.ec.custom.sec;
