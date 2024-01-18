import subprocess
import shlex
import os
import time


def killProcesses():
    # kill running processes
    # M
    os.system("kill -9 $(lsof -t -i:3500)")
    # P
    os.system("kill -9 $(lsof -t -i:4450)")
    # SP
    os.system("kill -9 $(lsof -t -i:5111)")


def launchProcesses():
    launch_M = shlex.split("sh ./run_manager.sh")
    launch_P = shlex.split("sh ./run_peripheral.sh")
    launch_gdb = shlex.split("gdb python3")

    # launch process for manager M
    p_M = subprocess.Popen(launch_M, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # launch process for peripheral P
    p_P = subprocess.Popen(launch_P, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # launch process for peripheral P
    p_gdb = subprocess.Popen(launch_gdb, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(1)
    return p_gdb


def gdbInput(process, cmd):
    process.stdin.write(cmd.encode('utf-8'))
    process.stdin.flush()
    time.sleep(0.4)


def get_flag_one(p_gdb):
    gdbInput(p_gdb, "set auto-load safe-path\n")
    gdbInput(p_gdb, "set follow-fork-mode child\n")
    gdbInput(p_gdb, "set pagination off\n")
    gdbInput(p_gdb, "set breakpoint pending on\n")
    gdbInput(p_gdb, "break gcm_crypt_and_tag\n")
    gdbInput(p_gdb, "run sp_server.py\n")
    gdbInput(p_gdb, "c\n")
    gdbInput(p_gdb, 'set gcm_crypt_and_tag::input = "<mes><action type=\\"key-update\\"/></mes>"\n')
    gdbInput(p_gdb, "c\n")

    start_RP = shlex.split("sh ./start.sh")
    p_RP = subprocess.Popen(start_RP, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def get_flag_two(p_gdb):
    gdbInput(p_gdb, "set auto-load safe-path\n")
    gdbInput(p_gdb, "set follow-fork-mode child\n")
    gdbInput(p_gdb, "set pagination off\n")
    gdbInput(p_gdb, "set breakpoint pending on\n")
    gdbInput(p_gdb, "break stringParser\n")
    gdbInput(p_gdb, "run sp_server.py\n")
    gdbInput(p_gdb, "break *stringParser+1568\n")
    gdbInput(p_gdb, "break *stringParser+1659\n")
    gdbInput(p_gdb, "break *stringParser+1687\n")
    gdbInput(p_gdb, "c\n")
    gdbInput(p_gdb, "set $eax = 0x7d316c\n")
    gdbInput(p_gdb, "c\n")
    gdbInput(p_gdb, "set $rax = redeemer[3]\n")
    gdbInput(p_gdb, "c\n")
    gdbInput(p_gdb, "set $al = 0x11\n")
    gdbInput(p_gdb, "d\n")
    gdbInput(p_gdb, "y\n")
    gdbInput(p_gdb, "detach\n")

    start_RP = shlex.split("sh ./start.sh")
    p_RP = subprocess.Popen(start_RP, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def main():
    # go to directory of t1
    #os.chdir("/home/theresa/isl_module06/t1")       # local
    os.chdir("/home/isl/t1")                         # vm

    #--------------------------------------START TASK 1.1--------------------------------------
    killProcesses()
    p_gdb = launchProcesses()

    get_flag_one(p_gdb)
    time.sleep(1)
    print("Flag 1, done!")
    time.sleep(3)
    #--------------------------------------START TASK 1.2--------------------------------------

    killProcesses()
    p_gdb = launchProcesses()

    get_flag_two(p_gdb)
    time.sleep(1)
    print("Flag 2, done!")
    time.sleep(3)


if __name__ == "__main__":
    main()

