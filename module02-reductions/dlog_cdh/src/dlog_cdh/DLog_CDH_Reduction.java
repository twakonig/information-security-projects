package dlog_cdh;

import java.math.BigInteger;
import java.util.Random;

import cdh.CDH_Challenge;
import dlog.DLog_Challenge;
import dlog.I_DLog_Challenger;
import genericGroups.IGroupElement;
import utils.NumberUtils;
import utils.Pair;
import utils.StringUtils;
import utils.Triple;

/**
 * This is the file you need to implement.
 * 
 * Implement the method {@code run} of this class.
 * Do not change the constructor of this class.
 */
public class DLog_CDH_Reduction extends A_DLog_CDH_Reduction<IGroupElement, BigInteger> {

    /**
     * You will need this field.
     */
    private CDH_Challenge<IGroupElement> cdh_challenge;
    /**
     * Save here the group generator of the DLog challenge given to you.
     */
    private IGroupElement generator;

    /**
     * Do NOT change or remove this constructor. When your reduction can not provide
     * a working standard constructor, the TestRunner will not be able to test your
     * code and you will get zero points.
     */
    public DLog_CDH_Reduction() {
        // Do not add any code here!
    }

    @Override
    public BigInteger run(I_DLog_Challenger<IGroupElement> challenger) {
        // This is one of the both methods you need to implement.

        // By the following call you will receive a DLog challenge.
        DLog_Challenge<IGroupElement> challenge = challenger.getChallenge();
        this.generator = challenge.generator;

        // check if x = 0
        if (challenge.x.equals(this.generator.power(BigInteger.ZERO))) {
            return BigInteger.ZERO;
        }

        // else x != 0 lies in multiplicative group Z_p_x
        // find group order of challenge
        BigInteger groupOrder = this.generator.getGroupOrder();

        // get generetor z of multiplicative group Z_p_x
        BigInteger z = PrimesHelper.getGenerator(groupOrder);

        // search for k s.t. x = z^k

        // decomposition of ord(group) - 1: [q_0, ...., q_l-1]
        // ord(groupe) - 1 = q_0 * q_1 * ... * q_l-1
        int[] q_array = PrimesHelper.getDecompositionOfPhi(groupOrder);

        // empty array for g^x_i
        // IGroupElement[] x_array = new IGroupElement[q_array.length];

        // empty array for k values
        int[] k_array = new int[q_array.length];
        IGroupElement x_i;

        // iterate through array of small primes q_i
        for (int i = 0; i < q_array.length; i++) {
            // compute x_i = g^x^((p-1)/q_i)
            // p = groupOrder
            BigInteger mod_inv_qi = BigInteger.valueOf(q_array[i]).modInverse(groupOrder);
            BigInteger exponent = groupOrder.subtract(BigInteger.ONE).multiply(mod_inv_qi).mod(groupOrder);
            x_i = cdh_power(challenge.x, exponent);
            // k loop to fill k_array
            for (int k = 0; k < q_array[i]; k++) {
                // compute z^...
                BigInteger z_exponent = BigInteger.valueOf(k)
                        .multiply(groupOrder.subtract(BigInteger.ONE).multiply(mod_inv_qi)).mod(groupOrder);
                IGroupElement z_k = cdh_power(this.generator.power(z), z_exponent);

                if (z_k.equals(x_i)) {
                    k_array[i] = k;
                }
            }
        }

        // use chinese remainder theorem to find k
        BigInteger k = CRTHelper.crtCompose(k_array, q_array);

        // x == z^k
        BigInteger e = z.modPow(k, groupOrder);
        return e;
    }

    @Override
    public CDH_Challenge<IGroupElement> getChallenge() {
        // There is not really a reason to change any of the code of this method.
        return cdh_challenge;
    }

    /**
     * For your own convenience, you should write a cdh method for yourself that,
     * when given group elements g^x and g^y, returns a group element g^(x*y)
     * (where g is the generator from the DLog challenge).
     */
    private IGroupElement cdh(IGroupElement x, IGroupElement y) {
        // Use the run method of your CDH adversary to have it solve CDH-challenges:

        // use the adversary to square elements in group
        this.cdh_challenge = new CDH_Challenge<IGroupElement>(this.generator, x, y);
        IGroupElement cdh_solution = adversary.run(this);

        return cdh_solution;
    }

    /**
     * For your own convenience, you should write a cdh_power method for yourself
     * that,
     * when given a group element g^x and a number k, returns a group element
     * g^(x^k) (where g is the generator from the DLog challenge).
     */
    // square and multiply, returns gX^exponent
    private IGroupElement cdh_power(IGroupElement gX, BigInteger exponent) {
        // For this method, use your cdh method and think of aritmetic algorithms for
        // fast exponentiation.
        // Use the methods exponent.bitLength() and exponent.testBit(n)!

        // account for first bit
        IGroupElement sol = this.generator.power(BigInteger.ONE);

        // compute x_i = g^x^exp
        int bits = exponent.bitLength();

        for (int i = exponent.bitLength() - 1; i >= 0; i--) {
            // square always
            sol = cdh(sol, sol);
            // bit is 1, also multiply
            if (exponent.testBit(i)) {
                // sol = sol.multiply(gX);
                sol = cdh(sol, gX);
            }
        }
        return sol;
    }
}
