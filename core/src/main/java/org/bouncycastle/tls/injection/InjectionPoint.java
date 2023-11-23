package org.bouncycastle.tls.injection;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.tls.injection.sigalgs.InjectedSigAlgorithm;

import java.util.Stack;

public class InjectionPoint {
    private final Stack<InjectableAlgorithms> injectionStack;


    // Bill Pugh Singleton Implementation, see https://www.geeksforgeeks.org/java-singleton-design-pattern-practices-examples/
    private static class BillPughSingleton {
        private static final InjectionPoint INSTANCE = new InjectionPoint();
    }

    // private = do not allow to call the constructor directly; force using _new
    private InjectionPoint() {
        this.injectionStack = new Stack<>();
    }

    public static InjectionPoint _new() {
        return BillPughSingleton.INSTANCE;
    }

    /**
     * Injects (pushes) the given algorithms into BouncyCastle TLS implementation.
     *
     * @param newAlgorithms the algorithms to inject
     * @throws IllegalStateException if another set of InjectableAlgorithms has already been injected (pushed).
     *                               In this case, use pushAfter() to be able to push the new algorithms instead of the previous.
     *                               Alternatively, use pop() to withdraw all previously injected algorithms and push() the new set of algorithms.
     */
    public synchronized void push(InjectableAlgorithms newAlgorithms) throws IllegalStateException {
        if (!injectionStack.isEmpty())
            throw new IllegalStateException("Some other algorithms have been already injected (pushed).");

        injectionStack.push(newAlgorithms);
    }

    /**
     * Injects (pushes) the current InjectableAlgorithms into BouncyCastle TLS implementation
     * by replacing (staging into the stack) the previously injected algorithms.
     *
     * @param newAlgorithms the algorithms to inject
     * @param previous      the previously injected algorithms (works as a "token" that allows us to "overwrite" them)
     * @throws IllegalStateException if the previously injected algorithms do not match the " previous" argument.
     *                               In this case, use pop() to withdraw all previously injected algorithms and push() the new set of algorithms.
     */
    public synchronized void pushAfter(InjectableAlgorithms newAlgorithms, InjectableAlgorithms previous) throws IllegalStateException {
        if (injectionStack.isEmpty())
            throw new IllegalStateException("No previously injected (pushed) algorithms found.");
        if (!injectionStack.peek().equals(previous))
            throw new IllegalStateException("The previously injected (pushed) algorithms do not match the previous argument.");
        injectionStack.push(newAlgorithms);
    }

    /**
     * Withdraws (pops) the current set of algorithms and restores the previously injected algorithms (if any).
     * @param current the currently used injected algorithms (act as a key to withdraw)
     * @throws IllegalStateException if no InjectableAlgorithms have been pushed
     */
    public synchronized void pop(InjectableAlgorithms current) throws IllegalStateException {
        if (injectionStack.isEmpty())
            throw new IllegalStateException("No previously injected (pushed) algorithms found.");
        if (!injectionStack.peek().equals(current))
            throw new IllegalStateException("The currently used injected (pushed) algorithms do not match the current argument.");
        injectionStack.pop();
    }


    ///// for BC TLS

    private static InjectableKEMs dummyKems = new InjectableKEMs();
    private static InjectableSigAlgs dummySigAlgs = new InjectableSigAlgs();

    public static InjectableKEMs kems() {
        InjectableAlgorithms algs = BillPughSingleton.INSTANCE.injectionStack.peek();
        if (algs == null)
            return dummyKems;
        return algs.kems();
    }

    public static InjectableSigAlgs sigAlgs() {
        InjectableAlgorithms algs = BillPughSingleton.INSTANCE.injectionStack.peek();
        if (algs == null)
            return dummySigAlgs;
        return algs.sigAlgs();
    }

    public synchronized static void configureProvider(ConfigurableProvider provider) {

        // TODO: call not only from BouncyCastlePQCProvider, but also from JSSE?
        InjectableAlgorithms algs = BillPughSingleton.INSTANCE.injectionStack.peek();
        for (InjectedSigAlgorithm alg : sigAlgs().asSigAlgCollection()) {

            new Registrar(alg.oid(), alg.name(), alg.converter()).configure(provider);
        }
    }

    private static class Registrar extends AsymmetricAlgorithmProvider {
        private final ASN1ObjectIdentifier oid;
        private final String name;
        private final AsymmetricKeyInfoConverter converter;

        public Registrar(ASN1ObjectIdentifier oid, String name, AsymmetricKeyInfoConverter converter) {
            super();
            this.oid = oid;
            this.name = name;
            this.converter = converter;
        }

        @Override
        public void configure(ConfigurableProvider provider) {
            try {
                provider.addAlgorithm("Alg.Alias.Signature." + this.oid, this.name);
                provider.addAlgorithm("Alg.Alias.Signature.OID." + this.oid, this.name);
            } catch (IllegalStateException e) {
                // ignore, if duplicate (needed for injected RSA)
            }

            // remove previous values in order to avoid the duplicate key exception
            if (provider instanceof java.security.Provider) {
                java.security.Provider p = (java.security.Provider) provider;
                p.remove("Signature." + this.name);
                p.remove("Alg.Alias.Signature." + this.oid);
                p.remove("Alg.Alias.Signature.OID." + this.oid);
            }
            // = provider.addSignatureAlgorithm(provider, "SPHINCSPLUS", PREFIX + "SignatureSpi$Direct", BCObjectIdentifiers.sphincsPlus);
            provider.addAlgorithm("Signature." + this.name, "org.bouncycastle.tls.injection.signaturespi.DirectSignatureSpi");
            provider.addAlgorithm("Alg.Alias.Signature." + this.oid, this.name);
            provider.addAlgorithm("Alg.Alias.Signature.OID." + this.oid, this.name);


            try {
                registerOid(provider, this.oid, this.name, converter);
                registerOidAlgorithmParameters(provider, this.oid, this.name);
            } catch (IllegalStateException e) {
                // ignore, if duplicate (needed for injected RSA)
            }
            provider.addKeyInfoConverter(this.oid, converter);
        }
    }

}
