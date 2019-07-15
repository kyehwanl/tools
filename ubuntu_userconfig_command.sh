
echo '-------------------------'
echo '  update'
echo '-------------------------'
sudo apt update

#-----------------
# Misc
#-----------------
echo '-------------------------------------'
echo ' Misc: build essential and net-tools'
echo '-------------------------------------'
sudo apt install -y build-essential net-tools


#----------
#  git
#----------
echo '-------------------------'
echo '  git'
echo '-------------------------'
sudo apt install -y git


#---------------
# screnn & tmux
#---------------
echo '-------------------------'
echo '  tmux screen'
echo '-------------------------'
sudo apt install -y tmux screen



#----------
#  vifm
#----------

# pre-requisite: additional library install for vifm
echo '-------------------------'
echo '  libncursesw5-dev'
echo '-------------------------'
sudo apt install -y libncursesw5-dev
sudo apt install -y autoconf

# download vifm from sourceforge (http://prdownloads.sourceforge.net/vifm/vifm-0.10.tar.bz2?download)
# or download from github
echo '-------------------------'
echo '  vifm download from github'
echo '-------------------------'
git clone https://github.com/vifm/vifm.git /tmp/vifm
cd /tmp/vifm
autoreconf -i
./configure && make && sudo make install


# compile & install vifm
#bunzip2 vifm-0.10.tar.bz2
#tar -C /path/toinstall -xvf vifm-0.10.tar
#cd vifm-0.10
#make all
#sudo make install


#-------------------
# cscope and ctags
#  - cscope: need check in Software & Updates - Ubuntu Software - Community-maintained free
#-------------------
echo '-------------------------'
echo '  cscope ctags'
echo '-------------------------'
sudo apt install -y cscope ctags




#-------------------
#   my config
#-------------------
echo '-------------------------'
echo '  my config'
echo '-------------------------'
git clone https://github.com/kyehwanl/note.git /tmp/note
cd /tmp/note/
cp config_and_diff_patch/tmux-conf_tips/_tmux.conf ~/.tmux.conf
mkdir -p ~/.vifm/colors
cp config_and_diff_patch/vifmrc ~/.vifm/
cp config_and_diff_patch/MyColorScheme.vifm ~/.vifm/colors/
cp config_and_diff_patch/emulab-conf/gitconfig.emulab.20141117 ~/.gitconfig
cp config_and_diff_patch/emulab-conf/screenrc.emulab.20141117 ~/.screenrc
cp config_and_diff_patch/.gitignore ~/


#-------------------
# vim & plugins
#-------------------
echo '-------------------------'
echo '  vim & plugins'
echo '-------------------------'
sudo apt install -y vim

# spf13, vim plugins
sudo apt install -y curl
sh <(curl https://j.mp/spf13-vim3 -L)



#-------------------
#  Project
#-------------------
echo '-------------------------'
echo '  SRx Crypto API'
echo '-------------------------'
sudo apt install -y openssl libssl-dev libconfig-dev uthash-dev
git clone https://github.com/kyehwanl/api_priv.git /tmp/

#-------------------
#  Korean Language
#-------------------
# ref http://blog.naver.com/PostView.nhn?blogId=robot7887&logNo=221496699314&parentCategoryNo=&categoryNo=102&viewDate=&isShowPopularPosts=true&from=search

#ibus-setup






