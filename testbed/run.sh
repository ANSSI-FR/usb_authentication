#!/usr/bin/bash

set -o errexit -o pipefail -o nounset

readonly PROJECT_ROOT=$(dirname $(realpath "${0}"))
readonly BUILD_DIR="${PROJECT_ROOT}/build"

readonly PKI_DST_PATH="${BUILD_DIR}/PKI"
readonly ROOT_STORE_PATH="${BUILD_DIR}/root_store"

readonly ENGINE_SRC_PATH="${PROJECT_ROOT}/src/policy_engine"
readonly ENGINE_DST_PATH="${BUILD_DIR}/policy_engine/"

readonly QEMU_DEVICE="usb_device"
readonly QEMU_DST_PATH="${BUILD_DIR}/qemu"
readonly QEMU_BIN_PATH="${QEMU_DST_PATH}/build/qemu-system-x86_64"
readonly QEMU_OPTS="-device qemu-xhci -device usb-auth,pcap=qemu_usb_log.pcap -usb_auth_config ${BUILD_DIR}/${QEMU_DEVICE}_dev_config.json"

# Patches and source configuration
readonly PATCH_SRC_DIR="${PROJECT_ROOT}/../patches"

readonly LINUX_SRC_PATH="${BUILD_DIR}/linux"
readonly LINUX_VERSION="v6.15.2"
readonly LINUX_CONFIG_DIR="${PROJECT_ROOT}/src/config/"

readonly QEMU_SRC_PATH="${PROJECT_ROOT}/src/qemu"
readonly QEMU_VERSION="4e66a08546a2588a4667766a1edab9caccf24ce3"

function prepare() {
	git submodule update --init --recursive
	git config --global user.email "you@example.com"
	git config --global user.name "Your Name"
}

function compile_qemu() {
	[ ! -d "${QEMU_DST_PATH}" ] && git clone https://gitlab.com/qemu-project/qemu.git "${QEMU_DST_PATH}"
	pushd "${QEMU_DST_PATH}"
		git reset --hard "${QEMU_VERSION}"
		git am "${PATCH_SRC_DIR}/qemu/"*.patch --no-gpg-sign
		[[ ! -d "build" ]] && mkdir "build"
		pushd "build"
			../configure --disable-bzip2 --disable-curl --disable-linux-aio --disable-libdw --disable-af-xdp --disable-vde --disable-lzo --disable-vnc-sasl --disable-vnc-jpeg --disable-fuse --disable-slirp --disable-libnfs --disable-docs --enable-debug --target-list="x86_64-softmmu"
			make -j $(nproc)
		popd
	popd
}

function compile_kernel() {
	[ ! -d "${LINUX_SRC_PATH}" ] && git clone https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git --depth=1 --branch "${LINUX_VERSION}" "${LINUX_SRC_PATH}"
	pushd "${LINUX_SRC_PATH}"
		git reset --hard "${LINUX_VERSION}"
		git am "${PATCH_SRC_DIR}/linux/"*.patch --no-gpg-sign
		vng -b --config ${LINUX_CONFIG_DIR}/config
	popd
}

function compile_policy_engine() {
	pushd src/policy_engine/mbedtls/
	make -j $(nproc)
	popd
	make -C "${ENGINE_SRC_PATH}"
	[ ! -d "${ENGINE_DST_PATH}" ] && mkdir "${ENGINE_DST_PATH}"
	install "${ENGINE_SRC_PATH}/policy_engine" "${ENGINE_DST_PATH}"
}

function config_pki() {
	[ ! -d "${PKI_DST_PATH}" ] && mkdir "${PKI_DST_PATH}"
	./src/pki/main.py -s "${PKI_DST_PATH}" --pki PKI
	./src/pki/main.py -s "${PKI_DST_PATH}" --device ${QEMU_DEVICE} --vid 4242 --pid 2121

	install "${PKI_DST_PATH}/${QEMU_DEVICE}"_dev_config.json "${BUILD_DIR}/${QEMU_DEVICE}"_dev_config.json

	[ ! -d "${ROOT_STORE_PATH}" ] && mkdir "${ROOT_STORE_PATH}"
	install "${PKI_DST_PATH}/root_cert.pem" "${ROOT_STORE_PATH}/"
}

function run() {
	vng --append "loglevel=7" --run "${LINUX_SRC_PATH}" --user root --qemu "${QEMU_BIN_PATH}" --verbose --qemu-opts="${QEMU_OPTS}"
}

function build() {
	prepare
	compile_qemu
	compile_kernel
	compile_policy_engine
	config_pki
}

function test() {
	vng --append "loglevel=7" --run "${LINUX_SRC_PATH}" --user root --qemu "${QEMU_BIN_PATH}" --verbose --qemu-opts="${QEMU_OPTS}" -- \
	"${ENGINE_SRC_PATH}/policy_engine" --root_store "${ROOT_STORE_PATH}/"
}

for option in "${@}"
do
	case "${option}" in
		--build)
			build
			exit
		;;
		--run)
			run
			exit
		;;
		--test)
		    test
		    exit
		;;
		*)
		;;
	esac
done
