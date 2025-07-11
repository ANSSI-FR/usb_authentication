# Get the parent directory path in order to expose a similar path in the build container
# Its needed because qemu create symbolic links of bios based on its cwd.
# BUILD_DIR		= /build
MK_PATH:=$(dir $(realpath $(lastword $(MAKEFILE_LIST))))
MK_PARENT:=$(realpath $(MK_PATH)../)
BUILD_DIR	= $(MK_PARENT)
RESOURCES_DIR	= $(BUILD_DIR)/Resources/

all: build

container_build:
	podman build --net host --file Containerfile --tag usb_auth . --build-arg WD=$(BUILD_DIR)

PODMAN := podman run --rm -it \
			--network host \
			--volume ../:$(BUILD_DIR):Z \
			usb_auth 

CMD := $(PODMAN) \
       ./run.sh

build: container_build
	$(CMD) --build

run:
	./run.sh --run

test:
	./run.sh --test

docs:
	$(PODMAN) ./run.sh --docs

clean:
	rm -rf build/*

.PHONY: all clean container_build test run
