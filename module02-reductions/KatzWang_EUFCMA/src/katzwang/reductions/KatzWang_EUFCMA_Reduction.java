package katzwang.reductions;

import java.math.BigInteger;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;

import ddh.DDH_Challenge;
import ddh.I_DDH_Challenger;
import genericGroups.IGroupElement;
import katzwang.A_KatzWang_EUFCMA_Adversary;
import katzwang.KatzWangPK;
import katzwang.KatzWangSignature;
import katzwang.KatzWangSolution;
import utils.NumberUtils;
import utils.Pair;
import utils.StringUtils;
import utils.Triple;

public class KatzWang_EUFCMA_Reduction extends A_KatzWang_EUFCMA_Reduction {

    // attributes
    IGroupElement g;
    IGroupElement gX;
    IGroupElement gY;
    IGroupElement gZ;
    HashMap<Triple<IGroupElement, IGroupElement, String>, BigInteger> hashes = new HashMap<>();

    public KatzWang_EUFCMA_Reduction(A_KatzWang_EUFCMA_Adversary adversary) {
        super(adversary);
        // Do not change this constructor
    }

    @Override
    public Boolean run(I_DDH_Challenger<IGroupElement, BigInteger> challenger) {

        // receive a DDH challenge
        DDH_Challenge<IGroupElement> challenge = challenger.getChallenge();

        // set attributes
        this.g = challenge.generator;
        this.gX = challenge.x;
        this.gY = challenge.y;
        this.gZ = challenge.z;

        // solution from adversary: message, signature
        KatzWangSolution<BigInteger> solution = adversary.run(this);

        // check null case
        if (solution == null) {
            return false;
        }

        // signature from solution: c, s
        KatzWangSignature<BigInteger> sig = solution.signature;
        String m = solution.message;

        // initialize c and s
        BigInteger c = sig.c;
        BigInteger s = sig.s;

        // initialize values to verify signature
        IGroupElement g_s = this.g.power(s);
        IGroupElement y1_c = this.gX.power(c);
        IGroupElement h_s = this.gY.power(s);
        IGroupElement y2_c = this.gZ.power(c);

        IGroupElement comm1_ver = g_s.multiply(y1_c.invert());
        IGroupElement comm2_ver = h_s.multiply((y2_c.invert()));
        Triple<IGroupElement, IGroupElement, String> key_ver = new Triple<IGroupElement, IGroupElement, String>(
                comm1_ver, comm2_ver, m);

        // retrieve hash of key_ver and check if valid signature
        if (hashes.containsKey(key_ver)) {
            BigInteger hash_ver = hashes.get(key_ver);
            // compare hash_ver with c to check validity
            if (hash_ver.equals(c)) {
                // valid signature, real tuple
                return true;
            } else {
                return false;
            }
        } else {
            // random tuple
            return false;
        }
    }

    @Override
    public KatzWangPK<IGroupElement> getChallenge() {
        // set parameters from challenge for public key to pass
        // h = g^y
        IGroupElement g = this.g;
        IGroupElement h = this.gY;
        IGroupElement y1 = this.gX;
        IGroupElement y2 = this.gZ;

        // create public key
        KatzWangPK<IGroupElement> pk = new KatzWangPK<IGroupElement>(g, h, y1, y2);
        return pk;
    }

    // returns hash (random BigInteger) of input
    @Override
    public BigInteger hash(IGroupElement comm1, IGroupElement comm2, String message) {
        // define key as triple
        Triple<IGroupElement, IGroupElement, String> key = new Triple<IGroupElement, IGroupElement, String>(comm1,
                comm2, message);

        // return consistent value if key is already in map (mapped to Random BigInteger
        // in Z_p)
        if (this.hashes.containsKey(key)) {
            return this.hashes.get(key);
        } else {
            BigInteger hash = NumberUtils.getRandomBigInteger(new Random(), this.g.getGroupOrder());
            this.hashes.put(key, hash);
            return hash;
        }
    }

    // signature oracle for adversary
    @Override
    public KatzWangSignature<BigInteger> sign(String message) {

        // for yet unsigned messages construct random signature
        BigInteger c = NumberUtils.getRandomBigInteger(new Random(), this.g.getGroupOrder());
        BigInteger s = NumberUtils.getRandomBigInteger(new Random(), this.g.getGroupOrder());

        // precompute values
        IGroupElement g_s = this.g.power(s);
        IGroupElement y1_c = this.gX.power(c);
        IGroupElement h_s = this.gY.power(s);
        IGroupElement y2_c = this.gZ.power(c);

        // compute comm1 and comm2
        IGroupElement comm1 = g_s.multiply(y1_c.invert());
        IGroupElement comm2 = h_s.multiply(y2_c.invert());

        // program hash function from sign function
        this.hashes.put(new Triple<IGroupElement, IGroupElement, String>(comm1, comm2, message), c);

        // return randomly generated signature
        KatzWangSignature<BigInteger> sig = new KatzWangSignature<BigInteger>(c, s);

        return sig;
    }
}
