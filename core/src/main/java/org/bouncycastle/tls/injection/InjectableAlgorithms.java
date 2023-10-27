package org.bouncycastle.tls.injection;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.tls.injection.kems.KemFactory;
import org.bouncycastle.tls.injection.sigalgs.SigAlgAPI;

public class InjectableAlgorithms {

    ///// KEMs
    private final InjectableKEMs kems;
    private final InjectableSigAlgs sigAlgs;


    public InjectableAlgorithms() {
        this(new InjectableKEMs(), new InjectableSigAlgs());
    }

    private InjectableAlgorithms(InjectableKEMs kems, InjectableSigAlgs sigAlgs) {
        this.kems = kems;
        this.sigAlgs = sigAlgs;
    }

    private InjectableAlgorithms(InjectableAlgorithms origin) { // clone constructor
        this.kems = new InjectableKEMs(origin.kems);
        this.sigAlgs = new InjectableSigAlgs(origin.sigAlgs);
    }


    public InjectableAlgorithms withKEM(int kemCodePoint,
                                        String standardName, KemFactory kemFactory, InjectableKEMs.Ordering ordering) {
        return new InjectableAlgorithms(
                this.kems.withKEM(kemCodePoint, standardName, kemFactory, ordering),
                new InjectableSigAlgs(this.sigAlgs)
        );
    }

    public InjectableAlgorithms withoutKEM(int kemCodePoint) {
        return new InjectableAlgorithms(
                this.kems.withoutKEM(kemCodePoint),
                this.sigAlgs
        );
    }

    public InjectableAlgorithms withoutDefaultKEMs() {
        return new InjectableAlgorithms(
                this.kems.withoutDefaultKEMs(),
                this.sigAlgs
        );
    }

    public InjectableAlgorithms withSigAlg(String name,
                                           ASN1ObjectIdentifier oid,
                                           int signatureSchemeCodePoint,
                                           SigAlgAPI api) {
        InjectableAlgorithms clone = new InjectableAlgorithms(this);
        clone.sigAlgs().add(name, oid, signatureSchemeCodePoint, api);
        return clone;
    }

    public InjectableKEMs kems() {
        return this.kems;
    }

    public InjectableSigAlgs sigAlgs() {
        return this.sigAlgs;
    }


}
