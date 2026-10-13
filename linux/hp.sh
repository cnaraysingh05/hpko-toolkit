cd ~/Downloads
git clone https://github.com/cnaraysingh05/hpko-toolkit.git
mkdir -p hpko-toolkit/linux
pbpaste > hpko-toolkit/linux/hp.sh
chmod +x hpko-toolkit/linux/hp.sh
bash -n hpko-toolkit/linux/hp.sh && echo SYNTAX_OK