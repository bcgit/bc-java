package org.bouncycastle.tls.injection;

import org.bouncycastle.tls.injection.kems.InjectedKEM;
import org.bouncycastle.tls.injection.kems.KemFactory;

import java.util.*;

public class InjectableKEMs {
    public enum Ordering { BEFORE, AFTER };

    ///// KEMs
    private final List<Integer> kemsBefore;
    private final boolean useDefaultKems;
    private final List<Integer> kemsAfter;
    private final Map<Integer, InjectedKEM> code2kem;

    public InjectableKEMs() {
        this.kemsBefore = new LinkedList<>();
        this.useDefaultKems = true;
        this.kemsAfter = new LinkedList<>();
        this.code2kem = new HashMap<>();

    }

    InjectableKEMs(InjectableKEMs origin) { // clone constructor
        this(origin, origin.useDefaultKems);
    }
    private InjectableKEMs(InjectableKEMs origin, boolean useDefaultKems) { // clone constructor
        this.kemsBefore = new LinkedList<>(origin.kemsBefore);
        this.useDefaultKems = useDefaultKems;
        this.kemsAfter = new LinkedList<>(origin.kemsAfter);
        this.code2kem = new HashMap<>(origin.code2kem);
    }

    public InjectableKEMs withKEM(int kemCodePoint,
                                  String standardName, KemFactory kemFactory, Ordering ordering) {
        if (code2kem.containsKey(kemCodePoint))
            throw new RuntimeException("KEM code point "+kemCodePoint+" already exists.");

        InjectedKEM kem = new InjectedKEM(kemCodePoint, standardName, kemFactory);

        InjectableKEMs clone = new InjectableKEMs(this);
        clone.code2kem.put(kemCodePoint, kem);
        if (ordering == Ordering.BEFORE)
            clone.kemsBefore.add(kemCodePoint);
        else
            clone.kemsAfter.add(kemCodePoint);
        return clone;
    }

    public InjectableKEMs withoutKEM(int kemCodePoint) {
        if (!code2kem.containsKey(kemCodePoint))
            throw new RuntimeException("KEM code point "+kemCodePoint+" does not exist.");

        InjectableKEMs clone = new InjectableKEMs(this);
        clone.code2kem.remove(kemCodePoint);

        int i = clone.kemsBefore.indexOf(kemCodePoint);
        if (i>=0)
            clone.kemsBefore.remove(i);

        i = clone.kemsAfter.indexOf(kemCodePoint);
        if (i>=0)
            clone.kemsAfter.remove(i);
        return clone;
    }

    public InjectableKEMs withoutDefaultKEMs() {
        return new InjectableKEMs(this, false);
    }

    public boolean contain(int codePoint) {
        return code2kem.containsKey(codePoint);
    }

    public InjectedKEM kemByCodePoint(int codePoint) {
        return code2kem.get(codePoint);
    }

    public Collection<InjectedKEM> kemsByOrdering(Ordering ordering) {
        if (ordering == Ordering.BEFORE)
            return kemsBefore.stream().map(code2kem::get).toList();
        else
            return kemsAfter.stream().map(code2kem::get).toList();
    }

    public Collection<Integer> asCodePointCollection(Ordering ordering) {
        if (ordering == Ordering.BEFORE)
            return new LinkedList<>(kemsBefore);
        else
            return new LinkedList<>(kemsAfter);
    }

    public Collection<Integer> asCodePointCollection() {
        List<Integer> result = new LinkedList<>(kemsBefore);
        result.addAll(kemsAfter);
        return result;
    }

    public boolean defaultKemsNeeded() {
        return useDefaultKems;
    }

    public InjectedKEM firstKEM() {


        Collection<InjectedKEM> kems = kemsByOrdering(InjectableKEMs.Ordering.BEFORE);
        if (!kems.isEmpty())
            return kems.iterator().next();

        kems = kemsByOrdering(InjectableKEMs.Ordering.AFTER);
        if (!kems.isEmpty())
            return kems.iterator().next();

        throw new IllegalStateException("No KEM injected");
    }

}
