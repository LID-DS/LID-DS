###########################################################
#	Install Script for clean Ubuntu 18.04                 #
###########################################################

#Prerequesites
sudo apt update
sudo apt-get install -y apt-transport-https ca-certificates curl gnupg-agent software-properties-common imagemagick
sudo apt-get install -y build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev wget llvm libncurses5-dev libncursesw5-dev xz-utils tk-dev libffi-dev liblzma-dev python-openssl git tshark
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io
curl -s https://s3.amazonaws.com/download.draios.com/stable/install-sysdig | sudo bash
su - $(whoami) -c "curl -L https://github.com/pyenv/pyenv-installer/raw/master/bin/pyenv-installer | sudo bash"
echo 'export PATH="$HOME/.pyenv/bin:$PATH"' >> /home/$(whoami)/.bashrc
echo 'eval "$(pyenv init -)"' >> /home/$(whoami)/.bashrc
echo 'eval "$(pyenv virtualenv-init -)"' >> /home/$(whoami)/.bashrc
curl -s https://s3.amazonaws.com/download.draios.com/stable/install-sysdig | sudo bash

unzip lid_ds/sim/datasets/Archiv.zip -d lid_ds/sim/datasets/
