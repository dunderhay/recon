#!/bin/bash

#Original author memN0ps. Modifications by Phish

TOOLS_DIR="$HOME/tools"
WORDLISTS_DIR="$HOME/wordlists"
WORKING_DIR="$HOME/Desktop"
WORDLISTS=("https://github.com/danielmiessler/SecLists" "https://github.com/fuzzdb-project/fuzzdb" "https://github.com/swisskyrepo/PayloadsAllTheThings")


display_usage() {
  echo -e '----------------------------------------------'
  echo -e "[*] Usage: ./recon.sh -h                    (this page)"
  echo -e "[*] Usage: ./recon.sh -s                    (installs tools and wordlists)"
  echo -e "[*] Usage: ./recon.sh -r -d example.com     (perform recon on domain)"
  echo -e '----------------------------------------------'
}

setup_tools(){
  echo -e '----------------------------------------------'
  echo -e '[*] Installing tools and dependencies.'
  echo -e '----------------------------------------------'
  # Check if command line tools are installed
  if [[ -x "$(command -v go)" ]]; then
    echo -e '[+] Go is installed.'
  else
    echo -e "[-] Go is not installed.\n[+] Installing Go..."
    brew install golang
  fi

  if [[ -x "$(command -v unzip)" ]]; then
    echo -e '[+] Unzip is installed.'
  else
    echo -e "[-] Unzip is not installed.\n[+] Installing Unzip..."
    brew install unzip
  fi

  if [[ -x "$(command -v git)" ]]; then
    echo -e '[+] Git is installed.'
  else
    echo -e "[-] Git is not installed.\n[+] Installing Git..."
    brew install git
  fi

  # Check for tools directory, create it if does not exist
  if [ -d "$TOOLS_DIR" ]; then
    echo -e "[+] Tools directory found $TOOLS_DIR."
  else
    echo -e "[-] $TOOLS_DIR does not exist.\n[!] Creating tools directory..."
    mkdir -p $TOOLS_DIR
    echo -e "[+] $TOOLS_DIR directory created."
  fi

  # Check for Sublist3r directory, download and install if not found
  if [ -d "$TOOLS_DIR/Sublist3r/" ]; then
    echo -e "[*] Sublist3r installed."
  else
    echo -e "[-] Sublist3r is not installed.\n[!] Installing Sublist3r..."
    git clone "https://github.com/aboul3la/Sublist3r" "$TOOLS_DIR/Sublist3r/"
    cd "$TOOLS_DIR/Sublist3r/"
    echo -e "[!] Installing Sublist3r dependencies..."
    pip install -r requirements.txt --user
    echo -e "[+] Sublist3r installed."
  fi

  # massdns is not replaced by shuffledns
  Check for massdns directory, download and install if not found
  if [ -d "$TOOLS_DIR/massdns/" ]; then
    echo -e "[+] massdns installed."
  else
    echo -e "[-] massdns is not installed.\n[!] Installing massdns..."
    git clone "https://github.com/blechschmidt/massdns" "$TOOLS_DIR/massdns/"
    echo -e "[!] Compiling massdns..."
    cd "$TOOLS_DIR/massdns/" && make nolinux
    echo -e "[+] massdns installed."
  fi

  # Check for aquatone directory, download and install if not found
  if [ -d "$TOOLS_DIR/aquatone/" ]; then
    echo -e "[+] aquatone installed."
  else
    echo -e "[-] aquatone is not installed.\n[!] Installing aquatone..."
    mkdir -p "$TOOLS_DIR/aquatone/" && cd "$TOOLS_DIR/aquatone/"
    curl -L "https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_macos_amd64_1.7.0.zip" -o aquatone_v-1-7-0_mac.zip
    echo -e "[!] Extracting aquatone..."
    unzip aquatone_v-1-7-0_mac.zip && rm -f aquatone_v-1-7-0_mac.zip
    echo -e "[+] aquatone installed."
  fi

  # Check for amass directory, download and install if not found
  if [ -d "$TOOLS_DIR/amass/" ]; then
    echo -e "[+] amass installed."
  else
    echo -e "[-] amass is not installed.\n[!] Installing amass..."
    cd "$TOOLS_DIR"
    curl -L "https://github.com/OWASP/Amass/releases/download/v3.6.0/amass_v3.6.0_macos_amd64.zip" -o amass_v-3-6-0_mac.zip
    echo -e "[!] Extracting amass..."
    unzip amass_v-3-6-0_mac.zip && rm -f amass_v-3-6-0_mac.zip
    mv amass_v3.6.0_macos_amd64 amass
    echo -e "[+] amass installed."
  fi

  # Check for subfinder directory, download and install if not found
  if [ -d "$TOOLS_DIR/subfinder/" ]; then
    echo -e "[+] subfinder installed."
  else
    echo -e "[-] subfinder is not installed.\n[!] Installing subfinder..."
    mkdir -p "$TOOLS_DIR/subfinder/" && cd "$TOOLS_DIR/subfinder/"
    curl -L "https://github.com/projectdiscovery/subfinder/releases/download/v2.3.2/subfinder-darwin-amd64.tar" -o subfinder_v-2-3-2_mac.tar
    echo -e "[!] Extracting subfinder..."
    tar -xzf subfinder_v-2-3-2_mac.tar
    mv subfinder-darwin-amd64 subfinder
    rm -f subfinder_v-2-3-2_mac.tar
    echo -e "[+] subfinder installed.\n[*] Add your API keys to subfinders config file."
  fi

  # Check if go tools are installed
  go list github.com/tomnomnom/assetfinder &> /dev/null
  if [ $? -eq 0 ]; then
    echo -e "[+] assetfinder installed."
  else
    echo -e "[-] assetfinder is not installed.\n[+] Installing assetfinder..."
    go get -u github.com/tomnomnom/assetfinder
  fi

  go list github.com/tomnomnom/httprobe &> /dev/null
  if [ $? -eq 0 ]; then
    echo -e "[+] httprobe installed."
  else
    echo -e "[-] httprobe is not installed.\n[+] Installing httprobe..."
    go get -u github.com/tomnomnom/httprobe
  fi

  go list github.com/sensepost/gowitness &> /dev/null
  if [ $? -eq 0 ]; then
    echo -e "[+] gowitness installed."
  else
    echo -e "[-] gowitness is not installed.\n[+] Installing gowitness..."
    go get -u github.com/sensepost/gowitness
  fi

  go list github.com/projectdiscovery/shuffledns/cmd/shuffledns &> /dev/null
  if [ $? -eq 0 ]; then
    echo -e "[+] shuffledns installed."
  else
    echo -e "[-] shuffledns is not installed.\n[+] Installing shuffledns..."
    GO111MODULE=on go get -u github.com/projectdiscovery/shuffledns/cmd/shuffledns
  fi

  go list github.com/OJ/gobuster &> /dev/null
  if [ $? -eq 0 ]; then
    echo -e "[+] gobuster installed."
  else
    echo -e "[-] gobuster is not installed.\n[+] Installing gobuster..."
    go get -u github.com/OJ/gobuster
  fi

  go list github.com/ffuf/ffuf 2>&1 >/dev/null
  if [ $? -eq 0 ]; then
    echo -e "[+] ffuf installed."
  else
    echo -e "[-] ffuf is not installed.\n[+] Installing ffuf..."
    go get -u github.com/ffuf/ffuf
  fi


  echo -e '----------------------------------------------'
  echo -e '[*] Fetching wordlists.'
  echo -e '----------------------------------------------'

  if [ -d "$WORDLISTS_DIR" ]; then
    echo -e "[*] Wordlist directory found $WORDLISTS_DIR."
  else
    echo -e "[-] $WORDLISTS_DIR does not exist.\n[!] Creating wordlists directory..."
    mkdir -p "$WORDLISTS_DIR"
    echo -e "[+] $WORDLISTS_DIR directory created."
  fi

  # Get latest wordlists
  cd "$WORDLISTS_DIR"
  for WORDLIST in ${WORDLISTS[@]}
  do
    echo -e "[+] Fetching $WORDLIST."
    git clone "$WORDLIST"
  done
}


do_recon() {
  DOMAIN=$1
  echo -e "----------------------------------------------"
  echo -e "[*] Performing domain recon on $DOMAIN..."
  echo -e "----------------------------------------------\n"
  echo -e "----------------------------------------------"
  echo -e "[*] Running amass"
  echo -e "----------------------------------------------"
  # Run amass for domain name
  "$TOOLS_DIR"/amass/amass enum -passive -d $DOMAIN -o $WORKING_DIR/amass_subdomains.txt

  echo -e "----------------------------------------------"
  echo -e "[*] Running subfinder"
  echo -e "----------------------------------------------"
  # Run subfinder for domain name
  "$TOOLS_DIR"/subfinder/subfinder -d $DOMAIN -o $WORKING_DIR/subfinder_subdomains.txt

  echo -e "----------------------------------------------"
  echo -e "[*] Running assetfinder"
  echo -e "----------------------------------------------"
  # Run assetfinder for domain name
  ~/go/bin/assetfinder --subs-only $DOMAIN | tee -a $WORKING_DIR/assetfinder_subdomains.txt

  echo -e "----------------------------------------------"
  echo -e "[*] Running Sublist3r"
  echo -e "----------------------------------------------"
  # Starting sublist3r for domain name
  python3 "$TOOLS_DIR"/Sublist3r/sublist3r.py -d $DOMAIN -o $WORKING_DIR/sublist3r_subdomains.txt

  echo -e "----------------------------------------------"
  echo -e "[*] Sorting and uniquing found domain names"
  echo -e "----------------------------------------------"
  # Merge subdomains
  cat $WORKING_DIR/amass_subdomains.txt $WORKING_DIR/subfinder_subdomains.txt $WORKING_DIR/assetfinder_subdomains.txt  $WORKING_DIR/sublist3r_subdomains.txt >> $WORKING_DIR/unsorted_subdomains.txt

  # Remove duplicate entries
  sort -u $WORKING_DIR/unsorted_subdomains.txt -o $WORKING_DIR/merged_subdomains.txt

  echo -e "----------------------------------------------"
  echo -e "[*] Running massdns to determine live hosts"
  echo -e "----------------------------------------------"
  # Starting massdns -- massdns now replaced by shuffledns
  "$TOOLS_DIR"/massdns/bin/massdns $WORKING_DIR/merged_subdomains.txt -r $WORDLISTS_DIR/SecLists/Miscellaneous/dns-resolvers.txt -q -t A -o S -w $WORKING_DIR/alive_subdomains.txt

  #echo -e "----------------------------------------------"
  #echo -e "[*] Running shuffledns to determine live hosts"
  #echo -e "----------------------------------------------"
  # Run shuffledns to find alive hosts
  # ~/go/bin/shuffledns -list $WORKING_DIR/merged_subdomains.txt -r $WORDLISTS_DIR/SecLists/Miscellaneous/dns-resolvers.txt -silent -o $WORKING_DIR/alive_subdomains.txt

  echo -e "----------------------------------------------"
  echo -e "[*] Running httprobe to determine valid URLs"
  echo -e "----------------------------------------------"
  # Run httprobe to find URLs
  cat $WORKING_DIR/merged_subdomains.txt | ~/go/bin/httprobe -p http:80 -p http:443 http:8080 -p https:8443 | tee -a $WORKING_DIR/alive_URLs.txt

  echo -e "----------------------------------------------"
  echo -e "[*] Running gowitness to screenshot URLs"
  echo -e "----------------------------------------------"
  # Run gowitness to screenshot those URLs
  mkdir -p "$WORKING_DIR/gowitness_screenshots"
  ~/go/bin/gowitness file --source=$WORKING_DIR/alive_URLs.txt --threads=4 --resolution="1200,750" --log-format=json --log-level=warn --timeout=60 --destination=$WORKING_DIR/gowitness_screenshots

  # gowitness report generate
  # This should result in an report.html file with a screenshot report where screenshots are sorted using perception hashing.
  ~/go/bin/gowitness report generate --sort-perception

  echo -e "----------------------------------------------"
  echo -e "[*] Running aquatone"
  echo -e "----------------------------------------------"
  # Starting aquatone
  cat $WORKING_DIR/alive_subdomains.txt | "$TOOLS_DIR"/aquatone/aquatone -out aquatone
}


# Check whether user had supplied -h or --help . If yes display usage
if [[ ($1 == "--help") ||  ($1 == "-h") ]]; then
	display_usage
	exit 0
elif [[ ($1 == "--setup") ||  ($1 == "-s") ]]; then
  setup_tools
  exit 0
elif [[ ($1 == "-r") && ($2 == "-d") ]]; then
  if [[ ($3 != "") ]]; then
    do_recon $3
    exit 0
  else
    echo -e "[!] No domain name provided ヽ(•́o•̀)ノ"
    exit 1
  fi
fi

# TODO: Some projects use git releases - should pull from here to get the latest versions
# TODO: Option to update wordlists
