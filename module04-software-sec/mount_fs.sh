sudo apt install sshfs
sudo mkdir /mnt/islremotefs
sudo sshfs -o allow_other,IdentityFile=~/.ssh/isl_id_ed25519 -p 2224 student@isl-desktop1.inf.ethz.ch:/home/student/ /mnt/islremotefs/
