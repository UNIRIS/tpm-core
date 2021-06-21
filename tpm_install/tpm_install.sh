#/bin/bash

#assumes Elixir and Erlang are already installed on the system
mkdir tpm
cd tpm

sudo apt -y update
sudo apt -y install \
  autoconf-archive \
  libcmocka0 \
  libcmocka-dev \
  procps \
  iproute2 \
  build-essential \
  git \
  pkg-config \
  gcc \
  libtool \
  automake \
  libssl-dev \
  uthash-dev \
  autoconf \
  doxygen \
  libjson-c-dev \
  libini-config-dev \
  libcurl4-openssl-dev

git clone https://github.com/tpm2-software/tpm2-tss.git
cd tpm2-tss
./bootstrap
./configure --with-udevrulesdir=/etc/udev/rules.d
make -j$(nproc)

sudo make install
sudo sed -i 's/tss/uniris/gi' /etc/udev/rules.d/tpm-udev.rules
sudo udevadm control --reload-rules && sudo udevadm trigger
sudo ldconfig
sudo apt install tpm2-tools

cd ..
git clone https://github.com/UNIRIS/tpm-core.git
cd tpm-core
gcc support.c -o support stdio_helpers.c uniris-tpm.c -ltss2-esys
cd keygen
gcc keygen.c -o keygen ../uniris-tpm.c -ltss2-esys -lcrypto
FILENAME=`cat /sys/class/net/eno1/address`
echo "Generating Keys -- It may take 3-4 minutes"
./keygen > "$FILENAME"
echo "Done!"