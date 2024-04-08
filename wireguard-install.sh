#!/usr/bin/env bash

RED='\033[0;31m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

function isRoot() {
	if [ "${EUID}" -ne 0 ]; then
		echo "这个脚本需要 root 权限"
		exit 1
	fi
}

function checkVirt() {
	if [ "$(systemd-detect-virt)" == "openvz" ]; then
		echo "OpenVZ 不支持"
		exit 1
	fi

	if [ "$(systemd-detect-virt)" == "lxc" ]; then
		echo "LXC 不支持 (yet)."
		echo "从技术上讲，WireGuard 可以在 LXC 容器中运行，"
		echo "但是内核模块必须安装在主机上，"
		echo "容器必须使用一些特定的参数运行"
		echo "在集装箱中只需要安装工具。"
		exit 1
	fi
}

function checkOS() {
	source /etc/os-release
	OS="${ID}"
	if [[ ${OS} == "debian" || ${OS} == "raspbian" ]]; then
		if [[ ${VERSION_ID} -lt 10 ]]; then
			echo "Your version of Debian (${VERSION_ID}) is not supported. Please use Debian 10 Buster or later"
			exit 1
		fi
		OS=debian # overwrite if raspbian
	elif [[ ${OS} == "ubuntu" ]]; then
		RELEASE_YEAR=$(echo "${VERSION_ID}" | cut -d'.' -f1)
		if [[ ${RELEASE_YEAR} -lt 18 ]]; then
			echo "Your version of Ubuntu (${VERSION_ID}) is not supported. Please use Ubuntu 18.04 or later"
			exit 1
		fi
	elif [[ ${OS} == "fedora" ]]; then
		if [[ ${VERSION_ID} -lt 32 ]]; then
			echo "Your version of Fedora (${VERSION_ID}) is not supported. Please use Fedora 32 or later"
			exit 1
		fi
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		if [[ ${VERSION_ID} == 7* ]]; then
			echo "Your version of CentOS (${VERSION_ID}) is not supported. Please use CentOS 8 or later"
			exit 1
		fi
	elif [[ -e /etc/oracle-release ]]; then
		source /etc/os-release
		OS=oracle
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	else
		echo "Looks like you aren't running this installer on a Debian, Ubuntu, Fedora, CentOS, AlmaLinux, Oracle or Arch Linux system"
		exit 1
	fi
}

function getHomeDirForClient() {
	local CLIENT_NAME=$1

	if [ -z "${CLIENT_NAME}" ]; then
		echo "Error: getHomeDirForClient() requires a client name as argument"
		exit 1
	fi

	# Home directory of the user, where the client configuration will be written
	if [ -e "/home/${CLIENT_NAME}" ]; then
		# if $1 is a user name
		HOME_DIR="/home/${CLIENT_NAME}"
	elif [ "${SUDO_USER}" ]; then
		# if not, use SUDO_USER
		if [ "${SUDO_USER}" == "root" ]; then
			# If running sudo as root
			HOME_DIR="/root"
		else
			HOME_DIR="/home/${SUDO_USER}"
		fi
	else
		# if not SUDO_USER, use /root
		HOME_DIR="/root"
	fi

	echo "$HOME_DIR"
}

function initialCheck() {
	isRoot
	checkVirt
	checkOS
}

function installQuestions() {
	echo "安装 WireGuard!"
	echo "Git 仓库在: https://github.com/noaway/wireguard-install.sh"
	echo ""
	echo "在开始安装之前，需要完成以下步骤"
	echo "默认选项可以更改"
	echo ""

    SERVER_PUB_IP=$(curl ip.sb)
	read -rp "IPv4 公网地址: " -e -i "${SERVER_PUB_IP}" SERVER_PUB_IP


	SERVER_NIC="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
	until [[ ${SERVER_PUB_NIC} =~ ^[a-zA-Z0-9_]+$ ]]; do
		read -rp "网络接口: " -e -i "${SERVER_NIC}" SERVER_PUB_NIC
	done

	until [[ ${SERVER_WG_NIC} =~ ^[a-zA-Z0-9_]+$ && ${#SERVER_WG_NIC} -lt 16 ]]; do
		read -rp "WireGuard 接口名称: " -e -i wg0 SERVER_WG_NIC
	done

	until [[ ${SERVER_WG_IPV4} =~ ^([0-9]{1,3}\.){3} ]]; do
		read -rp "WireGuard 服务器网络地址(IPv4): " -e -i 10.10.10.1 SERVER_WG_IPV4
	done

	until [[ ${SERVER_PORT} =~ ^[0-9]+$ ]] && [ "${SERVER_PORT}" -ge 1 ] && [ "${SERVER_PORT}" -le 65535 ]; do
		read -rp "WireGuard 服务器监听端口号: " -e -i "9210" SERVER_PORT
	done

	until [[ ${CLIENT_DNS_1} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
		read -rp "第一个 DNS 地址: " -e -i 114.114.114.114 CLIENT_DNS_1
	done
	until [[ ${CLIENT_DNS_2} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
		read -rp "第二个 DNS 地址 (可选): " -e -i 8.8.8.8 CLIENT_DNS_2
		if [[ ${CLIENT_DNS_2} == "" ]]; then
			CLIENT_DNS_2="${CLIENT_DNS_1}"
		fi
	done

	until [[ ${ALLOWED_IPS} =~ ^.+$ ]]; do
		echo -e "\nWireGuard 使用一个名为 allowedip 的参数来确定通过 VPN 路由的内容。"
		read -rp "生成的客户端允许的ip列表 (将设置为默认路由): " -e -i \"${SERVER_WG_IPV4}/24\" ALLOWED_IPS
		if [[ ${ALLOWED_IPS} == "" ]]; then
			ALLOWED_IPS="${SERVER_WG_IPV4}/24"
		fi
	done

	echo ""
	echo "设置完成。现在准备搭建 WireGuard 服务器"
	echo "安装结束需要新增客户端"
	read -n1 -r -p "请按任意键继续..."
}

function installWireGuard() {
	installQuestions

	if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' && ${VERSION_ID} -gt 10 ]]; then
		apt-get update
		apt-get install -y wireguard iptables resolvconf qrencode
	elif [[ ${OS} == 'debian' ]]; then
		if ! grep -rqs "^deb .* buster-backports" /etc/apt/; then
			echo "deb http://deb.debian.org/debian buster-backports main" >/etc/apt/sources.list.d/backports.list
			apt-get update
		fi
		apt update
		apt-get install -y iptables resolvconf qrencode
		apt-get install -y -t buster-backports wireguard
	elif [[ ${OS} == 'fedora' ]]; then
		if [[ ${VERSION_ID} -lt 32 ]]; then
			dnf install -y dnf-plugins-core
			dnf copr enable -y jdoss/wireguard
			dnf install -y wireguard-dkms
		fi
		dnf install -y wireguard-tools iptables qrencode
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		if [[ ${VERSION_ID} == 8* ]]; then
			yum install -y epel-release elrepo-release
			yum install -y kmod-wireguard
			yum install -y qrencode # not available on release 9
		fi
		yum install -y wireguard-tools iptables
	elif [[ ${OS} == 'oracle' ]]; then
		dnf install -y oraclelinux-developer-release-el8
		dnf config-manager --disable -y ol8_developer
		dnf config-manager --enable -y ol8_developer_UEKR6
		dnf config-manager --save -y --setopt=ol8_developer_UEKR6.includepkgs='wireguard-tools*'
		dnf install -y wireguard-tools qrencode iptables
	elif [[ ${OS} == 'arch' ]]; then
		pacman -S --needed --noconfirm wireguard-tools qrencode
	fi

	mkdir /etc/wireguard >/dev/null 2>&1

	chmod 600 -R /etc/wireguard/

	SERVER_PRIV_KEY=$(wg genkey)
	SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | wg pubkey)

	# Save WireGuard settings
	echo "SERVER_PUB_IP=${SERVER_PUB_IP}
SERVER_PUB_NIC=${SERVER_PUB_NIC}
SERVER_WG_NIC=${SERVER_WG_NIC}
SERVER_WG_IPV4=${SERVER_WG_IPV4}
SERVER_PORT=${SERVER_PORT}
SERVER_PRIV_KEY=${SERVER_PRIV_KEY}
SERVER_PUB_KEY=${SERVER_PUB_KEY}
CLIENT_DNS_1=${CLIENT_DNS_1}
CLIENT_DNS_2=${CLIENT_DNS_2}
ALLOWED_IPS=${ALLOWED_IPS}" >/etc/wireguard/data

	# Add server interface
	echo "[Interface]
Address = ${SERVER_WG_IPV4}/24
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}" >"/etc/wireguard/${SERVER_WG_NIC}.conf"

	if pgrep firewalld; then
		FIREWALLD_IPV4_ADDRESS=$(echo "${SERVER_WG_IPV4}" | cut -d"." -f1-3)".0"
		echo "PostUp = firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'
PostDown = firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	else
		echo "PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostUp = ip6tables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	fi

	echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/wg.conf

	sysctl -p

	systemctl start "wg-quick@${SERVER_WG_NIC}"
	systemctl enable "wg-quick@${SERVER_WG_NIC}"

	newClient
	echo -e "${GREEN}如果想添加更多的客户端，您只需要再次运行此脚本!${NC}"

	systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
	WG_RUNNING=$?

	if [[ ${WG_RUNNING} -ne 0 ]]; then
		echo -e "\n${RED}警告: WireGuard 没有运行.${NC}"
		echo -e "${ORANGE}您可以检查 WireGuard 是否正在运行: systemctl status wg-quick@${SERVER_WG_NIC}${NC}"
		echo -e "${ORANGE}如果没有 \"找到设备 ${SERVER_WG_NIC}\", 请重启!${NC}"
	else 
        # WireGuard is running
		echo -e "\n${GREEN}WireGuard 正在运行。${NC}"
		echo -e "${GREEN}您可以使用命令查看 WireGuard 的状态: systemctl status wg-quick@${SERVER_WG_NIC}\n\n${NC}"
		echo -e "${ORANGE}如果您的客户端没有互联网连接，请尝试重新启动服务器。${NC}"
	fi
}

function newClient() {
	if [[ ${SERVER_PUB_IP} =~ .*:.* ]]; then
		if [[ ${SERVER_PUB_IP} != *"["* ]] || [[ ${SERVER_PUB_IP} != *"]"* ]]; then
			SERVER_PUB_IP="[${SERVER_PUB_IP}]"
		fi
	fi
	ENDPOINT="${SERVER_PUB_IP}:${SERVER_PORT}"

	echo ""
	echo "客户端配置"
	echo ""
	echo "户端名称必须由字母数字字符组成。它也可以包括下划线或破折号，不能超过 15 个字符。"

	until [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ && ${CLIENT_EXISTS} == '0' && ${#CLIENT_NAME} -lt 16 ]]; do
		read -rp "客户端名称: " -e CLIENT_NAME
		CLIENT_EXISTS=$(grep -c -E "^### Client ${CLIENT_NAME}" "/etc/wireguard/${SERVER_WG_NIC}.conf")

		if [[ ${CLIENT_EXISTS} != 0 ]]; then
			echo ""
			echo -e "${ORANGE}客户端已存在${NC}"
			echo ""
		fi
	done

	for DOT_IP in {2..254}; do
		DOT_EXISTS=$(grep -c "${SERVER_WG_IPV4::-1}${DOT_IP}" "/etc/wireguard/${SERVER_WG_NIC}.conf")
		if [[ ${DOT_EXISTS} == '0' ]]; then
			break
		fi
	done

	if [[ ${DOT_EXISTS} == '1' ]]; then
		echo ""
		echo "该子网只支持 253 个客户端。"
		exit 1
	fi

	BASE_IP=$(echo "$SERVER_WG_IPV4" | awk -F '.' '{ print $1"."$2"."$3 }')
	until [[ ${IPV4_EXISTS} == '0' ]]; do
		read -rp "客户端 WireGuard IPv4 地址: ${BASE_IP}." -e -i "${DOT_IP}" DOT_IP
		CLIENT_WG_IPV4="${BASE_IP}.${DOT_IP}"
		IPV4_EXISTS=$(grep -c "$CLIENT_WG_IPV4/32" "/etc/wireguard/${SERVER_WG_NIC}.conf")

		if [[ ${IPV4_EXISTS} != 0 ]]; then
			echo ""
			echo -e "${ORANGE}客户端 IPv4 地址已存在，请选更换.${NC}"
			echo ""
		fi
	done

	CLIENT_PRIV_KEY=$(wg genkey)
	CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | wg pubkey)
	CLIENT_PRE_SHARED_KEY=$(wg genpsk)

	HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")

	echo "[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_WG_IPV4}/32
DNS = ${CLIENT_DNS_1},${CLIENT_DNS_2}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = ${ALLOWED_IPS}
PersistentKeepalive=5" >"${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

	echo -e "\n### Client ${CLIENT_NAME} ${CLIENT_WG_IPV4}
[Peer]
PublicKey = ${CLIENT_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
AllowedIPs = ${CLIENT_WG_IPV4}/32" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"

	wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")

	# Generate QR code if qrencode is installed
	if command -v qrencode &>/dev/null; then
		echo -e "${GREEN}\n客户端配置文件的二维码:\n${NC}"
		qrencode -t ansiutf8 -l L <"${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"
		echo ""
	fi

	echo -e "${GREEN}用户配置文件存放在 ${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf${NC}"
}

function listClients() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	if [[ ${NUMBER_OF_CLIENTS} -eq 0 ]]; then
		echo ""
		echo "用户不存在!"
		exit 1
	fi

	grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | nl -s ') '
}

function rmClient() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
		echo ""
		echo "用户不存在!"
		exit 1
	fi

	echo ""
	echo "选择要删除的客户端"
	grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | nl -s ') '
	until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
		if [[ ${CLIENT_NUMBER} == '1' ]]; then
			read -rp "Select one client [1]: " CLIENT_NUMBER
		else
			read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
		fi
	done

	CLIENT_NAME=$(grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | sed -n "${CLIENT_NUMBER}"p)

	sed -i "/^${CLIENT_NAME}\$/,/^$/d" "/etc/wireguard/${SERVER_WG_NIC}.conf"

	HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")
	rm -f "${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

	wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")
}

function uninstallWg() {
	echo ""
	echo -e "\n${RED}警告:这将卸载 WireGuard 并删除所有配置文件!${NC}"
	echo -e "${ORANGE}如果保留配置文件，请备份 /etc/wireguard 目录。\n${NC}"
	read -rp "您要移除 WireGuard 吗? [y/n]: " -e REMOVE
	REMOVE=${REMOVE:-n}
	if [[ $REMOVE == 'y' ]]; then
		checkOS

		systemctl stop "wg-quick@${SERVER_WG_NIC}"
		systemctl disable "wg-quick@${SERVER_WG_NIC}"

		if [[ ${OS} == 'ubuntu' ]]; then
			apt-get remove -y wireguard wireguard-tools qrencode
		elif [[ ${OS} == 'debian' ]]; then
			apt-get remove -y wireguard wireguard-tools qrencode
		elif [[ ${OS} == 'fedora' ]]; then
			dnf remove -y --noautoremove wireguard-tools qrencode
			if [[ ${VERSION_ID} -lt 32 ]]; then
				dnf remove -y --noautoremove wireguard-dkms
				dnf copr disable -y jdoss/wireguard
			fi
		elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
			yum remove -y --noautoremove wireguard-tools
			if [[ ${VERSION_ID} == 8* ]]; then
				yum remove --noautoremove kmod-wireguard qrencode
			fi
		elif [[ ${OS} == 'oracle' ]]; then
			yum remove --noautoremove wireguard-tools qrencode
		elif [[ ${OS} == 'arch' ]]; then
			pacman -Rs --noconfirm wireguard-tools qrencode
		fi

		rm -rf /etc/wireguard
		rm -f /etc/sysctl.d/wg.conf

		sysctl -p

		systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
		WG_RUNNING=$?

		if [[ ${WG_RUNNING} -eq 0 ]]; then
			echo "WireGuard 无法卸载。"
			exit 1
		else
			echo "WireGuard 卸载成功。"
			exit 0
		fi
	else
		echo ""
		echo "删除失败!"
	fi
}

function manageMenu() {
	echo "Git 存储库可在: https://github.com/angristan/wireguard-install"
	echo ""
	echo "请选择选项数字进行相关操作"
	echo "   1) 新增用户"
	echo "   2) 列出所有用户"
	echo "   3) 删除用户"
	echo "   4) 卸载 WireGuard"
	echo "   5) 退出"
	until [[ ${MENU_OPTION} =~ ^[1-5]$ ]]; do
		read -rp "请选择数字 [1-5]: " MENU_OPTION
	done

	while true
	do
		case "${MENU_OPTION}" in
		1)
			newClient
			;;
		2)
			listClients
			;;
		3)
			rmClient
			;;
		4)
			uninstallWg
			;;
		5)
			exit 0
			;;
		esac
		read -rp "请选择数字 [1-5]: " MENU_OPTION
	done
}

main() {
    initialCheck

    if [[ -e /etc/wireguard/data ]]; then
        source /etc/wireguard/data
        manageMenu
    else
        installWireGuard
    fi
}

main $@