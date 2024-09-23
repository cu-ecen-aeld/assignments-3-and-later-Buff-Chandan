#!/bin/sh
# Script outline to install and build kernel.
# Author: Siddhant Jajoo.
#

set -e
set -u

OUTDIR=/tmp/aeld
KERNEL_REPO=git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git
KERNEL_VERSION=v5.15.163
BUSYBOX_VERSION=1_33_1
FINDER_APP_DIR=$(realpath $(dirname $0))
ARCH=arm64
CROSS_COMPILE=aarch64-none-linux-gnu-

if [ $# -lt 1 ]
then
	echo "Using default directory ${OUTDIR} for output"
else
	OUTDIR=$1
	echo "Using passed directory ${OUTDIR} for output"
fi

mkdir -p ${OUTDIR}

cd "$OUTDIR"
if [ ! -d "${OUTDIR}/linux-stable" ]; then
    #Clone only if the repository does not exist.
	echo "CLONING GIT LINUX STABLE VERSION ${KERNEL_VERSION} IN ${OUTDIR}"
	git clone ${KERNEL_REPO} --depth 1 --single-branch --branch ${KERNEL_VERSION}
fi
if [ ! -e ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ]; then
    cd linux-stable
    echo "Checking out version ${KERNEL_VERSION}"
    git checkout ${KERNEL_VERSION}


    # TODO: Add your kernel build steps here
    echo "Kernel build"
    make clean ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE}
    
    echo "config the virtual arm to simulate in QEMU"
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} default_config
    
    echo "create kernel image to boot with QEMU"
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} -j4 build_all
    
    echo "build kernel modules"
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} modules
    
    echo "build device tree"
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} device_tree_blobs
fi 


echo "Adding the Image in outdir"

cp ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ${OUTDIR}/Image


echo "Creating the staging directory for the root filesystem"
cd "$OUTDIR"
if [ -d "${OUTDIR}/rootfs" ]
then
	echo "Deleting rootfs directory at ${OUTDIR}/rootfs and starting over"
    sudo rm  -rf ${OUTDIR}/rootfs
fi

# TODO: Create necessary base directories
echo "Creating necessary directories for the file system"
mkdir -p ${OUTDIR}/rootfs

if [ ! -d "${OUTDIR}/rootfs" ]
then
	echo "Error: ${OUTDIR}/rootfs not created"
	exit 1
fi

cd ${OUTDIR}/rootfs
mkdir bin dev etc home lib lib64 proc sbin sys tmp usr var
mkdir usr/bin usr/lib usr/sbin
mkdir -p var/log


cd "$OUTDIR"
if [ ! -d "${OUTDIR}/busybox" ]
then
git clone git://busybox.net/busybox.git
    cd busybox
    git checkout ${BUSYBOX_VERSION}
    # TODO:  Configure busybox
    echo "configuring busybox"
make clean
make default_config
else
    cd busybox
fi


# TODO: Make and install busybox
echo "Building and installing BusyBox"
make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} all
make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} CONFIG_PREFIX=${OUTDIR}/rootfs install

echo "pointing back to rootfs"
cd ${OUTDIR}/rootfs


echo "Library dependencies"
${CROSS_COMPILE}readelf -a bin/busybox | grep "program interpreter"
${CROSS_COMPILE}readelf -a bin/busybox | grep "Shared library"

# TODO: Add library dependencies to rootfs

echo "Add library dependencies to rootfs"
SYSROOT=$(${CROSS_COMPILE}gcc -print-sysroot)
cd ${OUTDIR}/rootfs
cp $SYSROOT/lib/ld-linux-aarch64.so.1 lib
cp $SYSROOT/lib64/libm.so.6 lib64
cp $SYSROOT/lib64/libresolv.so.2 lib64
cp $SYSROOT/lib64/libc.so.6 lib64


# TODO: Make device nodes
echo "Make device nodes"
sudo mknod -m 666 dev/null c 1 3
sudo mknod -m 600 dev/console c 5 1


# TODO: Clean and build the writer utility
echo "Clean and build the writer utility"
cd $FINDER_APP_DIR
make clean 
make CROSS_COMPILE=${CROSS_COMPILE}

# TODO: Copy the finder related scripts and executables to the /home directory
# on the target rootfs	
echo "Copy the finder related scripts and executables to the /home directory"
cp -f $FINDER_APP_DIR/autorun-qemu.sh ${OUTDIR}/rootfs/home
cp -f $FINDER_APP_DIR/conf/ -r ${OUTDIR}/rootfs/home
cp -f $FINDER_APP_DIR/finder.sh ${OUTDIR}/rootfs/home
cp -f $FINDER_APP_DIR/finder-test.sh ${OUTDIR}/rootfs/home
cp -f $FINDER_APP_DIR/writer ${OUTDIR}/rootfs/home


# TODO: Chown the root directory
echo "Chown the root directory"
cd ${OUTDIR}/rootfs
sudo chown -R root:root *

# TODO: Create initramfs.cpio.gz
echo "Create initramfs.cpio.gz"
find . | cpio -H newc -ov --owner root:root > ../initramfs.cpio
cd ..
gzip -f initramfs.cpio

##EOF
