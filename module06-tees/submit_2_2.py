import os
import sys
import shutil

output_dir = "/home/isl/t2_2/output"
traces_dir = "/home/isl/t2_2/traces"
sgx_dir = "/home/isl/pin-3.11-97998-g7ecce2dac-gcc-linux-master/source/tools/SGXTrace"

pin_cmd_1 = "../../../pin -t ./obj-intel64/SGXTrace.so -o " + traces_dir + "/"
pin_cmd_2 = " -trace 1 -- /home/isl/t2_2/password_checker_2 "

# trace addresses
CORRECT_LETTER = '0x401d83'
WRONG_LETTER = '0x401d89'
RET_ADRR = '0x401db6'
COMPARE_LETTERS = '0x401d7f'


def main():
    # create/check output directory
    os.makedirs(output_dir, exist_ok=True)

    # remove traces directory if it already exists
    if os.path.exists(traces_dir):
        shutil.rmtree(traces_dir)

    # get arguments from command line
    if len(sys.argv) != 2:
        print("Usage: python3 submit_2_1.py <id>")
        sys.exit(1)
    id = sys.argv[1]

    filename = output_dir + '/' + 'oput_' + id
    input_guess = ''

    # create traces for chosen guesses and save them in traces_dir (a.txt, ..., z.txt)
    os.makedirs(traces_dir, exist_ok=True)
    os.chdir(sgx_dir)
    for i in range(0, 26):
        letter = chr(ord('a') + i)
        input_guess = letter * 34
        cmd = pin_cmd_1 + letter + ".txt" + pin_cmd_2 + input_guess
        os.system(cmd)
    os.chdir("/home/isl/t2_2")
    #------------------------------SETUP DONE-------------------------------------

    # reconstructed password
    pw = ['_'] * 34

    # variables for logic
    id_letter = -1
    pw_length = 0


    # go through all trace files in traces_dir
    for trace in os.listdir(traces_dir):
        guessed_letter = trace.split(".")[0]
        pw_length = 0

        # open one trace file and search for occurrences of CORRECT_LETTER in it (populate pw)
        with open(traces_dir + '/' + trace, 'r') as infile:
            for line in infile:
                if line.startswith('E'):
                    # logic to reconstruct password
                    addr = line.split(":")[1]

                    if addr == COMPARE_LETTERS:
                        pw_length += 1
                    if addr == CORRECT_LETTER:
                        id_letter += 1
                        pw[id_letter] = guessed_letter
                        continue
                    if addr == WRONG_LETTER:
                        id_letter += 1
                        continue
                    if addr == RET_ADRR:
                        id_letter = -1
                        break
                
    # treat length of pw
    password = ''.join(pw)
    password = password[:pw_length]

    with open(filename, 'w') as outfile:
        if '_' in password:
            outfile.write(password + ',partial')
        else:
            outfile.write(password + ',complete')

    # finally: delete folder with traces
    shutil.rmtree(traces_dir)


if __name__ == "__main__":
    main()


