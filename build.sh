#!/usr/bin/env sh
export ARCH="arm64"
export CROSS_COMPILE="aarch64-linux-gnu-"
# export KERNELDIR="/home/martin/Projects/aml/aml_repo/kernel/aml-4.9"
# export KERNELDIR="/home/martin/Projects/aml/aml_repo/buildroot/output/build/linux-amlogic-4.9-dev"
export KERNEL_SRC="/home/martin/Projects/aml/aml_repo/buildroot/output/build/linux-amlogic-4.9-dev"

make build
