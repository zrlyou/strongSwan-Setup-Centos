#!/bin/bash
# Author:		zrlyou<zrlyouwin@gmail.com>
# DateTime:		2017/08/07 15:00
# FileName:		strongSwan-Setup-Centos.sh
# Description:	strongSwan VPN Setup For Centos

# current user
CURRENT_USER="`whoami`"

# VPN server ip or domain name.Please change you VPN server IP or domain name here.
VPN_SERVER_HOST="10.20.105.30"

# cert path
CERT_PATH=~/cert

STRONGSWAN_PATH="/etc/strongswan"

# configs
IPSEC_CONF="${STRONGSWAN_PATH}/ipsec.conf"
STRONGSWAN_CONF="${STRONGSWAN_PATH}/strongswan.conf"
IPSEC_SECRETS="${STRONGSWAN_PATH}/ipsec.secrets"

if [ ! -e "${CERT_PATH}" ]; then
	mkdir -p "${CERT_PATH}"
fi

if [ "${CURRENT_USER}" != "root" ]; then
	echo "Please use 'root' user to run the script!"
	exit 1
fi


# env ensure
function env_ensure()
{	
	local selinux_config="/etc/selinux/config"
	local get_selinuc_config="`grep -e "^SELINUX=" "${selinux_config}" |awk -F "=" '{print $2}'`"
	if [ "${get_selinuc_config}" != "disabled" ]; then
		echo "The Selinux config is ${get_selinuc_config}, please set it 'SELINUX=disabled' path='${selinux_config}'"
		exit 1
	else
		echo "SELINUX=${get_selinuc_config}. Pass!"
	fi

	local sysctl_config="/etc/sysctl.conf"
	local get_ipv4_forward_value=`grep "net.ipv4.ip_forward" "${sysctl_config}" |awk -F "=" '{print $2}' | sed 's/[[:space:]]//g'`

	if [ -n "${get_ipv4_forward_value}" ]; then
		if [ $get_ipv4_forward_value -ne 1 ]; then
			echo "The config('net.ipv4.ip_forward') is not equal 1,will be set it 1"
			sed -i 's/net.ipv4.ip_forward = 0/net.ipv4.ip_forward = 1/g' "${sysctl_config}"
			if [ $? -eq 0 ]; then
				echo "Set 'net.ipv4.ip_forward = 1' is done!"
				sysctl -p
			else
				echo "Set 'net.ipv4.ip_forward = 1' is failed!Please check ${sysctl_config}"
				exit 1
			fi
		else
			echo "The config 'net.ipv4.ip_forward' is equal 1.Pass!"
		fi
	else
		echo "Please check the config of 'net.ipv4.ip_forward' is in ${sysctl_config}"
		exit 1
	fi
	
	local is_installed=`rpm -qa | grep strongswan | wc -l`
	if [ ${is_installed} -ne 0 ]; then
		echo "The strongswan was installed!Don't need to install!"
		exit 1
	fi
}

# echo cert info
function echo_cert_info()
{
	local status="$1"
	local cert_file_name="$2"
	local cert_file_path="$3"

	if [ "${status}" = "TRUE" ]; then
		echo "Generate cert file[${cert_file_name}] is done! Path:${cert_file_path}"
	else
		echo "Generate cert file[${cert_file_name}] failed! Path:${cert_file_path}"
		exit 1
	fi
}

# install strongswan
function install_strongswan()
{
	echo "Install strongswan ..."
	# install epel-release
	yum -y install epel-release
	yum -y install strongswan
	echo "Install strongsan is done!"	
}

# generate CA cert
function generate_CA_cert()
{
	local old_path=`pwd`
	
	cd "${CERT_PATH}"
	
	echo "Generate CA cert file in ${CERT_PATH}"

	strongswan pki --gen --outform pem > ca.pem
	if [ $? -eq 0 ]; then
		echo_cert_info "TRUE" "ca.pem" "${CERT_PATH}/ca.pem"
	else
		echo_cert_info "FALSE" "ca.pem" "${CERT_PATH}/ca.pem"
	fi

	strongswan pki --self --in ca.pem --dn "C=CN, O=sswvpn, CN=VPN CA" --ca --outform pem > ca.cert.pem
	if [ $? -eq 0 ]; then
		echo_cert_info "TRUE" "ca.cert.pem" "${CERT_PATH}/ca.cert.pem"
	else
		echo_cert_info "FALSE" "ca.cert.pem" "${CERT_PATH}/ca.cert.pem"
	fi

	cd "${old_path}"
}

# generate server cert
function generate_server_cert()
{
	local old_path=`pwd`
	
	cd "${CERT_PATH}"
	
	echo "Generate Server cert file in ${CERT_PATH}"
	
	strongswan pki --gen --outform pem > server.pem
	if [ $? -eq 0 ]; then
		echo_cert_info "TRUE" "server.pem" "${CERT_PATH}/server.pem"
	else
		echo_cert_info "FALSE" "server.pem" "${CERT_PATH}/server.pem"
	fi

	strongswan pki --pub --in server.pem | strongswan pki --issue --cacert ca.cert.pem --cakey ca.pem --dn "C=CN, O=zrlyou, CN=${VPN_SERVER_HOST}" --san="${VPN_SERVER_HOST}" --flag serverAuth --flag ikeIntermediate --outform pem > server.cert.pem
	if [ $? -eq 0 ]; then
		echo_cert_info "TRUE" "server.cert.pem" "${CERT_PATH}/server.cert.pem"
	else
		echo_cert_info "FALSE" "server.cert.pem" "${CERT_PATH}/server.cert.pem"
	fi

	cd "${old_path}"
}

# generate client cert
function generate_client_cert()
{
	local old_path=`pwd`
	
	cd "${CERT_PATH}"

	echo "Generate Client cert file in ${CERT_PATH}"
	
	strongswan pki --gen --outform pem > client.pem
	if [ $? -eq 0 ]; then
		echo_cert_info "TRUE" "client.pem" "${CERT_PATH}/client.pem"
	else
		echo_cert_info "FALSE" "client.pem" "${CERT_PATH}/client.pem"
	fi
	
	strongswan pki --pub --in client.pem | strongswan pki --issue --cacert ca.cert.pem --cakey ca.pem --dn "C=CN, O=zrlyou, CN=VPN Client" --outform pem > client.cert.pem
	if [ $? -eq 0 ]; then
		echo_cert_info "TRUE" "client.cert.pem" "${CERT_PATH}/client.cert.pem"
	else
		echo_cert_info "FALSE" "client.cert.pem" "${CERT_PATH}/client.cert.pem"
	fi

	cd "${old_path}"
}

# change client cert to pkcs12
function change_client_cert_to_pkcs12()
{
	local old_path=`pwd`
	
	cd "${CERT_PATH}"
	
	echo "Change Client cert to pkcs12.Please enter pskcs12 cert password:"
	
	openssl pkcs12 -export -inkey client.pem -in client.cert.pem -name "client" -certfile ca.cert.pem -caname "VPN CA" -out client.cert.p12
	if [ $? -eq 0 ]; then
		echo_cert_info "TRUE" "client.cert.p12" "${CERT_PATH}/client.cert.p12"
	else
		echo_cert_info "FALSE" "client.cert.p12" "${CERT_PATH}/client.cert.p12"
	fi

	cd "${old_path}"
}

# install all cert
function install_all_cert()
{
	local old_path=`pwd`
	local cacerts_path="/etc/strongswan/ipsec.d/cacerts"
	local certs_path="/etc/strongswan/ipsec.d/certs"
	local private_path="/etc/strongswan/ipsec.d/private"

	cd "${CERT_PATH}"

	echo "Install all cert files..."

	if [ -e "${cacerts_path}" ]; then
		cp -f ca.cert.pem "${cacerts_path}/"
	else
		echo "Can't find the path of ${cacerts_path}!"
		exit 1
	fi

	if [ -e "${certs_path}" ]; then
		cp -f server.cert.pem "${certs_path}/"
		cp -f client.cert.pem "${certs_path}/"
	else
		echo "Can't find the path of ${certs_path}!"
		exit 1
	fi

	if [ -e "${private_path}" ]; then
		cp -f server.pem "${private_path}/"
		cp -f client.pem "${private_path}/"
	else
		echo "Can't find the path of ${certs_path}!"
		exit 1
	fi

	echo "Install all cert files is done!"

	cd "${old_path}"
}

# set ipsec.conf file
function set_ipsec_conf()
{
	if [ -e "${IPSEC_CONF}" ]; then
		cp -f "${IPSEC_CONF}" "${IPSEC_CONF}_bak"
	fi

	echo "Set config for ${IPSEC_CONF}..."
	cat > "${IPSEC_CONF}" <<EOF
config setup
	# strictcrlpolicy=yes
	uniqueids = never

conn %default
	left = %any
	leftsubnet = 0.0.0.0/0
	right = %any
	rightsourceip = 10.10.10.0/24
	dpdaction = clear

conn IKEv1-CERT-XAUTH
	keyexchange = ikev1
	fragmentation = yes
	leftauth = pubkey
	leftcert = server.cert.pem
	rightauth = pubkey
	rightauth2 = xauth
	rightcert = client.cert.pem
	auto = add

conn IKEv1-PSK-XAUTH
	keyexchange = ikev1
	leftauth = psk
	rightauth = psk
	rightauth2 = xauth
	auto = add

conn IKEv2-CERT
	keyexchange = ikev2
	leftauth = pubkey
	leftcert = server.cert.pem
	rightauth = pubkey
	rightcert = client.cert.pem
	auto = add

conn IKEv2-EAP
	keyexchange = ikev2
	ike = aes256-sha256-modp1024,3des-sha1-modp1024,aes256-sha1-modp1024!
	esp = aes256-sha256,3des-sha1,aes256-sha1!
	rekey = no
	leftauth = pubkey
	leftcert = server.cert.pem
	leftsendcert = always
	leftid = ${VPN_SERVER_HOST}
	rightauth = eap-mschapv2
	rightsendcert = never
	eap_identity = %any
	fragmentation = yes
	auto = add
EOF
	if [ $? -eq 0 ]; then
		echo "Set config for ${IPSEC_CONF} is done!"
	else
		echo "Set config for ${IPSEC_CONF} is failed!"
		exit 1
	fi
}

# Set strongswan.conf
function set_strongswan_conf()
{
	if [ -e "${STRONGSWAN_CONF}" ]; then
		cp -f "${STRONGSWAN_CONF}" "${STRONGSWAN_CONF}_bak"
	fi
	
	echo "Set config for ${STRONGSWAN_CONF}..."
	cat > "${STRONGSWAN_CONF}" <<EOF
charon {
	load_modular = yes
	duplicheck.enable = no
	compress = yes
	plugins {
		include strongswan.d/charon/*.conf
	}
	dns1 = 8.8.8.8
	dns2 = 8.8.4.4
	nbns1 =  8.8.8.8
	nbns2 = 8.8.4.4

	filelog {
		/var/log/strongswan.log {
			time_format = %b %e %T
			default = 2
			append = no
			flush_line = yes
		}
	}
}

include strongswan.d/*.conf
EOF
	if [ $? -eq 0 ]; then
		echo "Set config for ${STRONGSWAN_CONF} is done!"
	else
		echo "Set config for ${STRONGSWAN_CONF} is failed!"
		exit 1
	fi
}

# Set ipsec.secerts
function set_ipsec_secerts()
{
	local psk_value="$1"
	
	if [ -e "${IPSEC_SECRETS}" ]; then
		cp -f "${IPSEC_SECRETS}" "${IPSEC_SECRETS}_bak"
	else
		touch "${IPSEC_SECRETS}"
	fi
	
	echo "Set ipsec.secerts..."

	cat > "${IPSEC_SECRETS}" <<EOF
# ipsec.secrets - strongSwan IPsec secrets file
: RSA server.pem
: PSK "${psk_value}"
EOF
	if [ $? -eq 0 ]; then
		echo "Set config for ${IPSEC_SECRETS} is done!"
	else
		echo "Set config for ${IPSEC_SECRETS} is failed!"
		exit 1
	fi
}

# add vpn user for connect
function add_vpn_user()
{
	local auth_way=

	echo "Add vpn user for connect:"
	read -p "Enter username:" username
	read -p "Enter password:" password
	echo "Choose authenticate way:"
	echo "1 ---------- XAUTH"
	echo "2 ---------- EAP"
	read -p "Please enter your number:" choose_num

	if [ ${choose_num} -eq 1 ]; then
		auth_way="XAUTH"
	else
		auth_way="EAP"
	fi

	if [ -e "${IPSEC_SECRETS}" ]; then
		echo "${username} : ${auth_way} \"${password}\"" >> "${IPSEC_SECRETS}"
		if [ $? -eq 0 ]; then
			echo "Add user ${username} is done!"
		else
			echo "Add user ${username} is failed!"
			exit 1
		fi
	fi
}


# set iptables rules
function set_iptables_rules()
{
	local interface="$1"
	
	echo "Set iptables rules..."
	
	iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
	iptables -A FORWARD -s 10.10.10.0/24  -j ACCEPT
	iptables -A INPUT -i "${interface}" -p udp --dport 500 -j ACCEPT
	iptables -A INPUT -i "${interface}" -p udp --dport 4500 -j ACCEPT
	iptables -A INPUT -j REJECT --reject-with icmp-host-prohibited
	iptables -A FORWARD -j REJECT --reject-with icmp-host-prohibited 
	iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o "${interface}" -j MASQUERADE
	/etc/init.d/iptables save
	iptables-save > /etc/sysconfig/iptables
	
	echo "Set iptables rules is done!"
}

# operate service
function operate_service()
{
	local service_name="$1"
	local operate="$2"
	
	echo "Service[${service_name}] ${operate}..."
	service "${service_name}" "${operate}"
	if [ $? -eq 0 ]; then
		echo "Service[${service_name}] ${operate} is done!"
	else
		echo "Service[${service_name}] ${operate} is failed!"
		exit 1
	fi
}

# start strongswan
function start_strongswan()
{
	operate_service "strongswan" "start"
}

# stop strongswan
function stop_strongswan()
{
	operate_service "strongswan" "stop"
}

# reload strongswan
function reload_strongswan()
{
	operate_service "strongswan" "reload"
}

# set strongswan onboot
function set_strongswan_onboot()
{
	chkconfig strongswan on
}

# remove strongswan
function remove_strongswan()
{
	local old_path=`pwd`
	yum -y remove strongswan
	echo "Delete all config files..."
	if [ -e "${STRONGSWAN_PATH}" ]; then
		rm -rf "${STRONGSWAN_PATH}"
		echo "Delete all config files is done!"
	fi
	
	echo "Delete all cert files..."
	
	if [ -e "${CERT_PATH}" ]; then
		cd "${CERT_PATH}"
		rm -rf *
		echo "Delete all cert files is done!"
	fi

	cd "${old_path}"	
}

# show help
function show_help()
{
	echo "Usage: sh strongSwan-Setup-Centos.sh options"
	echo "options:"
	echo "install				install strongswan and config strongswan."
	echo "remove				remove strongswan and delete all config files and cert files."
	echo "add_vpnuser			add vpn user to connect VPN server."
	echo "start				start strongswan service."
	echo "stop				stop strongswan service."
	echo "reload				reload strongswan service."
	echo "help or --help or -h		show help."
}

function main()
{
	local args=($@)
	local cmd="${args[0]}"
	
	case "${cmd}" in 
		install)
			env_ensure
			install_strongswan
			generate_CA_cert
			generate_server_cert
			generate_client_cert
			change_client_cert_to_pkcs12
			install_all_cert
			set_ipsec_conf
			set_strongswan_conf
			read -p "Please enter Pre-shared key:" share_key
			set_ipsec_secerts "${share_key}"
			echo "Network interface info:"
			ifconfig
			read -p "Please enter network interface:" get_interface
			set_iptables_rules "${get_interface}"
			add_vpn_user
			echo "strongswan is installed!"
			echo "You can download cert files[ca.cert.pem/client.cert.p12] in ${CERT_PATH}"
			ls -l "${CERT_PATH}/"
			read -p "Do you want to start strongswan service? y/n:" choose
			if [ "${choose}" = "y" -o "${choose}" = "Y" ]; then
				start_strongswan
			fi
			;;
		remove)
			read -p "Do you want to remove strongswan?[y/n]" is_remove
			if [ "${is_remove}" = "Y" -o "${is_remove}" = "y" ]; then
				remove_strongswan
			else
				echo "Exit!"
			fi
			;;
		add_vpnuser)
			add_vpn_user
			reload_strongswan
			;;
		start)
			start_strongswan
			;;
		stop)
			stop_strongswan
			;;
		reload)
			reload_strongswan
			;;
		help|--help|-h)
			show_help
			;;
		*)
			echo "Can't find the command[${cmd}]!"
			;;
	esac
}

main "$@"

