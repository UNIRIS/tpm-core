#/bin/bash

#*******************************************************************************
 #   Archethic TPM Library
 #   (c) 2021 Varun Deshpande, Uniris
 #
 #  Licensed under the GNU Affero General Public License, Version 3 (the "License");
 #  you may not use this file except in compliance with the License.
 #  You may obtain a copy of the License at
 #
 #      https://www.gnu.org/licenses/agpl-3.0.en.html
 #
 #  Unless required by applicable law or agreed to in writing, software
 #  distributed under the License is distributed on an "AS IS" BASIS,
 #  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 #  See the License for the specific language governing permissions and
 #  limitations under the License.
 #********************************************************************************

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
  libcurl4-openssl-dev \
  acl

git clone https://github.com/tpm2-software/tpm2-tss.git
cd tpm2-tss
./bootstrap
./configure --with-udevrulesdir=/etc/udev/rules.d
make -j$(nproc)

sudo make install
sudo sed -i "s/tss/$(whoami)/gi" /etc/udev/rules.d/tpm-udev.rules
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
