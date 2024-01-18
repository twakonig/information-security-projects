package cdh_quadratic;

import java.io.*;
import java.math.BigInteger;
import java.util.Random;

import cdh.CDH_Challenge;
import cdh.I_CDH_Challenger;
import genericGroups.IGroupElement;
import utils.NumberUtils;
import utils.Pair;
import utils.StringUtils;
import utils.Triple;

/**
 * This is the file you need to implement.
 * 
 * Implement the methods {@code run} and {@code getChallenge} of this class.
 * Do not change the constructor of this class.
 */
public class CDH_Quad_Reduction extends A_CDH_Quad_Reduction<IGroupElement> {

    // attributes
    IGroupElement g;
    IGroupElement gX;
    IGroupElement gY;

    /**
     * Do NOT change or remove this constructor. When your reduction can not provide
     * a working standard constructor, the TestRunner will not be able to test your
     * code and you will get zero points.
     */
    public CDH_Quad_Reduction() {
        // Do not add any code here!
    }

    // returns quadratic selfmap: g^(axy +bx + cy +d)
    public IGroupElement f1(IGroupElement g, IGroupElement gX, IGroupElement gY) {
        this.g = g;
        this.gX = gX;
        this.gY = gY;

        IGroupElement map_1 = adversary.run(this);
        return map_1;
    }

    // returns: g^(axy + bx + cy)
    public IGroupElement f2(IGroupElement g, IGroupElement gX, IGroupElement gY) {
        IGroupElement quad_selfmap = f1(g, gX, gY);

        // compute g^d (setting X and Y to 0)
        IGroupElement g_d = f1(g, g.power(BigInteger.ZERO), g.power(BigInteger.ZERO));

        // compute: g^(axy + bx + cy)
        IGroupElement g_d_inv = g_d.invert();
        IGroupElement map_2 = quad_selfmap.multiply(g_d_inv);
        return map_2;
    }

    // returns: g^(axy + bx)
    public IGroupElement f3(IGroupElement g, IGroupElement gX, IGroupElement gY) {
        IGroupElement quad_selfmap = f1(g, gX, gY);

        // compute g^(cy + d)
        IGroupElement set_x_0 = f1(g, g.power(BigInteger.ZERO), gY);

        // compute g^(axy + bx)
        IGroupElement set_x_0_inv = set_x_0.invert();
        IGroupElement map_3 = quad_selfmap.multiply(set_x_0_inv);
        return map_3;
    }

    // compute g^axy
    public IGroupElement f4(IGroupElement g, IGroupElement gX, IGroupElement gY) {
        // compute g^(axy + bx + d)
        IGroupElement num = f3(g, gX, gY);
        IGroupElement g_d = f1(g, g.power(BigInteger.ZERO), g.power(BigInteger.ZERO));
        IGroupElement num_d = num.multiply(g_d);

        // compute g^(bx + d)
        IGroupElement set_y_0 = f1(g, gX, g.power(BigInteger.ZERO));

        // compute g^axy
        IGroupElement set_y_0_inv = set_y_0.invert();
        IGroupElement map_4 = num_d.multiply(set_y_0_inv);
        return map_4;
    }

    @Override
    public IGroupElement run(I_CDH_Challenger<IGroupElement> challenger) {
        // This is one of the both methods you need to implement.

        // By the following call you will receive a DLog challenge.
        CDH_Challenge<IGroupElement> challenge = challenger.getChallenge();

        // generator
        IGroupElement g = challenge.generator;

        // compute g_xy
        IGroupElement g_a = f4(g, g.power(BigInteger.ONE), g.power(BigInteger.ONE));
        IGroupElement g_xy = f4(g_a, challenge.x, challenge.y);

        return g_xy;
    }

    @Override
    public CDH_Challenge<IGroupElement> getChallenge() {

        // This is the second method you need to implement.
        // You need to create a CDH challenge here which will be given to your CDH
        // adversary.
        IGroupElement generator = this.g;
        IGroupElement x = this.gX;
        IGroupElement y = this.gY;
        // Instead of null, your cdh challenge should consist of meaningful group
        // elements.
        CDH_Challenge<IGroupElement> cdh_challenge = new CDH_Challenge<IGroupElement>(generator, x, y);

        return cdh_challenge;
    }
}
