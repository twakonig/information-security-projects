import os
import sys

output_dir = "/home/isl/t2_1/output"

# trace addresses
ITER_FOR_LOOP = '0x40120d'  # if condition to compare letters (num. letters of shorter word)
CORRECT_LETTER = '0x401211'

INCR_DISTANCE = '0x40127e'  # num. of time j is decremented

GUESS_CORRECT = '0x4012a8'  # return 1
GUESS_WRONG = '0x4012af'    # return 0


def main():
    # create/check output directory
    os.makedirs(output_dir, exist_ok=True)

    # get arguments from command line
    if len(sys.argv) != 3:
        print("Usage: python3 submit_2_1.py <traces_dir> <id>")
        sys.exit(1)
    traces_dir = sys.argv[1]
    id = sys.argv[2]

    filename = output_dir + '/' + 'oput_' + id
    max_trace = ''

    # go through all files in traces_dir (each traces has a different guess) and find longest
    for trace in os.listdir(traces_dir):
        if len(trace) > len(max_trace):
            max_trace = trace

    trace_file = traces_dir + '/' + max_trace
    guessed_pw = max_trace.split(".")[0]


    # counter for correct letters
    k = 0
    # string of reconstructed password
    pw = ""
    id_letter = -1
    distance = 0

    # read trace file
    with open(trace_file, 'r') as infile:
        for line in infile:
            if line.startswith('E'):
                # logic to reconstruct password
                addr = line.split(":")[1]
    
                # next iteration of outer for loop
                if addr == ITER_FOR_LOOP:
                    if distance != 0:
                        real_letter = (ord(guessed_pw[id_letter]) - ord('a') + distance) % 26
                        pw += chr(real_letter + ord('a'))
                        distance = 0

                    id_letter += 1
                    continue

                if addr == CORRECT_LETTER:
                    k += 1
                    pw += guessed_pw[id_letter]
                    continue

                if addr == INCR_DISTANCE:
                    distance += 1
                    continue

                if addr == GUESS_CORRECT and k == len(guessed_pw):
                    if distance != 0:
                        real_letter = (ord(guessed_pw[id_letter]) - ord('a') + distance) % 26
                        pw += chr(real_letter + ord('a'))
                        distance = 0
                    # write pw to ouptut file, add complete
                    with open(filename, 'w') as outfile:
                        outfile.write(pw + ',complete')
                    return

                if addr == GUESS_WRONG:
                    if distance != 0:
                        real_letter = (ord(guessed_pw[id_letter]) - ord('a') + distance) % 26
                        pw += chr(real_letter + ord('a'))
                        distance = 0
                    # write pw to ouptut file
                    with open(filename, 'w') as outfile:
                        if id_letter < len(guessed_pw):
                            outfile.write(pw + ',complete')
                        else:
                            outfile.write(pw + ',partial')
                    return


if __name__ == "__main__":
    main()
