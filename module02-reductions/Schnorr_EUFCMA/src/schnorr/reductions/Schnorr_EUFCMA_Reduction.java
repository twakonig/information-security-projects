package schnorr.reductions;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Random;

import java.io.*;
import dlog.DLog_Challenge;
import dlog.I_DLog_Challenger;
import genericGroups.IGroupElement;
import schnorr.I_Schnorr_EUFCMA_Adversary;
import schnorr.SchnorrSignature;
import schnorr.SchnorrSolution;
import schnorr.Schnorr_PK;
import utils.NumberUtils;
import utils.Pair;
import utils.StringUtils;
import utils.Triple;

public class Schnorr_EUFCMA_Reduction extends A_Schnorr_EUFCMA_Reduction {

    // attributes
    IGroupElement g;
    IGroupElement gX;
    HashMap<Pair<String, IGroupElement>, BigInteger> hashes = new HashMap<>();

    public Schnorr_EUFCMA_Reduction(I_Schnorr_EUFCMA_Adversary<IGroupElement, BigInteger> adversary) {
        super(adversary);
        // Do not change this constructor!
    }

    @Override
    public Schnorr_PK<IGroupElement> getChallenge() {
        // set parameters from challenge for public key
        IGroupElement base = this.g;
        IGroupElement key = this.gX;

        // create public key
        Schnorr_PK<IGroupElement> pk = new Schnorr_PK<>(base, key);
        return pk;
    }

    @Override
    public SchnorrSignature<BigInteger> sign(String message) {
        // for yet unsigned messages construct random signature
        BigInteger c = NumberUtils.getRandomBigInteger(new Random(), this.g.getGroupOrder());
        BigInteger s = NumberUtils.getRandomBigInteger(new Random(), this.g.getGroupOrder());

        // calculate random value from signature
        IGroupElement g_s = this.g.power(s);
        IGroupElement pk_c = this.gX.power(c);
        IGroupElement R = g_s.multiply(pk_c.invert());

        // program hash function from sign function
        this.hashes.put(new Pair<String, IGroupElement>(message, R), c);

        // retrun randomly generated signature
        SchnorrSignature<BigInteger> sig = new SchnorrSignature<BigInteger>(c, s);

        return sig;
    }

    @Override
    public BigInteger hash(String message, IGroupElement r) {
        // define key as pair
        Pair<String, IGroupElement> key = new Pair<>(message, r);

        // return consistent hash value if key already exists
        if (this.hashes.containsKey(key)) {
            return this.hashes.get(key);
        } else {
            // hash value c
            BigInteger hash = NumberUtils.getRandomBigInteger(new Random(), this.g.getGroupOrder());
            this.hashes.put(key, hash);
            return hash;
        }
    }

    // check whethter signature is valid
    public boolean verify(String message, BigInteger c, BigInteger s) {

        // precomputations
        IGroupElement g_s = this.g.power(s);
        IGroupElement y_c = this.gX.power(c);
        IGroupElement comm = g_s.multiply(y_c.invert());

        // define the key
        Pair<String, IGroupElement> key = new Pair<>(message, comm);

        // return true if signature is valid
        if (this.hashes.get(key).equals(c)) {
            return true;
        } else {
            return false;
        }
    }

    @Override
    public BigInteger run(I_DLog_Challenger<IGroupElement> challenger) {

        // receive a DLOG challenge
        DLog_Challenge<IGroupElement> challenge = challenger.getChallenge();

        // set attributes
        this.g = challenge.generator;
        this.gX = challenge.x;

        // check edge case where x==0
        if (challenge.x.equals(challenge.generator.power(BigInteger.ZERO))) {
            return BigInteger.ZERO;
        }

        // set seed of adversary
        Random random_gen = new Random();
        long seed = random_gen.nextLong();
        adversary.reset(seed);

        // run adversary and save c1, s1
        SchnorrSolution<BigInteger> solution1 = adversary.run(this);

        // check null case
        if (solution1 == null) {
            return null;
        }

        // extract c1, s1
        SchnorrSignature<BigInteger> sig1 = solution1.signature;
        BigInteger c1 = sig1.c;
        BigInteger s1 = sig1.s;

        // reset seed and clear hashmap
        hashes.clear();
        adversary.reset(seed);

        // run adversary and save c2, s2
        SchnorrSolution<BigInteger> solution2 = adversary.run(this);

        // check null case
        if (solution2 == null) {
            return null;
        }

        // extract c2, s2
        SchnorrSignature<BigInteger> sig2 = solution2.signature;
        BigInteger c2 = sig2.c;
        BigInteger s2 = sig2.s;

        // compute return value (ret) from c1, c2, s1, s2
        BigInteger num = s1.subtract(s2);
        BigInteger den = c1.subtract(c2);
        BigInteger mod_inv = den.modInverse(this.g.getGroupOrder());

        // set return value as DLOG of given challenge
        BigInteger ret = num.multiply(mod_inv).mod(this.g.getGroupOrder());

        // make sure result equals x (g^(ret) == g^x)
        if (this.g.power(ret).equals(this.gX)) {
            return ret;
        } else {
            // TODO: what to return?
            return null;
        }
    }
}
