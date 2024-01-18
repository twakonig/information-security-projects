package rsapkcs;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Random;

import utils.NumberUtils;
import utils.Pair;
import utils.StringUtils;
import utils.Triple;

import static utils.NumberUtils.getRandomBigInteger;
import static utils.NumberUtils.ceilDivide;
import static utils.NumberUtils.getCeilLog;

public class RSAPKCS_OWCL_Adversary implements I_RSAPKCS_OWCL_Adversary {
    public RSAPKCS_OWCL_Adversary() {
        // Do not change this constructor!
    }

    /*
     * @see basics.IAdversary#run(basics.IChallenger)
     */
    @Override
    public BigInteger run(final I_RSAPKCS_OWCL_Challenger challenger) {
        // Write code here!

        // You can use all classes and methods from the util package:
        var randomNumber = NumberUtils.getRandomBigInteger(new Random(),challenger.getChallenge());
        var randomString = StringUtils.generateRandomString(new Random(), 10);
        var pair = new Pair<Integer, Integer>(5, 8);
        var triple = new Triple<Integer, Integer, Integer>(13, 21, 34);

        return BigInteger.ZERO;
    }
}