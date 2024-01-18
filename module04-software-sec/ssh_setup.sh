ssh-keygen -t ed25519 -f ~/.ssh/isl_id_ed25519

cat << EOF >> ~/.ssh/config
AddKeysToAgent yes
ServerAliveInterval 5
Host isl-env
  User student
  HostName isl-desktop1.inf.ethz.ch
  Port 2224
  IdentityFile ~/.ssh/isl_id_ed25519
EOF

eval $(ssh-agent)
ssh-add ~/.ssh/isl_id_ed25519

cat ~/.ssh/isl_id_ed25519.pub | ssh isl-env "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"
