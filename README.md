# MAPAlloc

This repository contains the reference implementation for MAPAlloc, a framework for prototyping memory-allocation based attacks and defenses on Linux. For technical information, please refer to the paper _'Taming the Linux Memory Allocator for Rapid
Prototyping'_ by Zhang, Hornetz, Gerlach, and Schwarz.

## Structure of this Repository
This repository consists of the following components:
 * `module` - The MAPAlloc kernel module.
 * `migrator` - A shared library for migrating a process's memory into memory ranges governed by MAPAlloc.
 * `utils` - Utilities for interfacing with MAPAlloc from the command line

## Building
Before building, make sure that you have the kernel headers installed. On Debian and Ubuntu, you can install them with the following command:
```shell
sudo apt-get install linux-headers-<your architecture>
```
You can then build MAPAlloc by running `make` in the repository folder.

## Using MAPAlloc
### Using the Kernel Module
First, load the kernel module with 
```shell
sudo insmod module/mapalloc.ko
```
and verify that the `/dev/color_allocator` allocator file exists.

To create a new allocator instance, use the `newexpr` program in the `utils` folder.
For example,
```shell
sudo ./newexpr "(x >> 12) & 31 == 0"
```
creates an allocator instance which provides pages where bits 12 to 16 of the physical address are zero.
For a complete reference on the DSL used by `newexpr`, please refer to the paper.

When done, `newexpr` will provide the ID of the newly created allocator instance.
To use it, open the `/dev/<ID>_match` file in your code, and use it with `mmap` in the same way as when mapping a file.

To delete an allocator instance, you can use the `delexpr` program.

For a reference on how to do all of the above purely in C code, see `utils/demo.c`.

### Using the Migrator Library
The migrator library re-maps a program's memory into physical memory managed by MAPAlloc.
This includes code segments and stack memory.
Furthermore, it will redirect all subsequent memory allocation with the `MAP_ANONYMOUS` flag to MAPAlloc.

You can either use the migrator _explicitly_, meaning that you link the library in your code and use its API, or _implicitly_, by pre-loading it using the dynamic linker.
In the latter case, the program can be completely oblivious to MAPAlloc, and the migration will happen before the main function executes.

See `migrator/mapalloc_migrator.h` for the migrator's explict interface.

For implicit use, you must configure the `LD_PRELOAD` and `ALLOC_FILE` environment variables.
For example, the following command will migrate the memory of the `cat` binary using `/dev/1_match`, and print the resulting memory map.
```shell
sudo LD_PRELOAD=<path to libmigrator.so> ALLOC_FILE=/dev/1_match cat /proc/self/maps
```
If successful, nearly all memory ranges should be governed by `/dev/1_match`.
Exceptions may include the kernel's VDSO range, and files explicitly mapped into memory post-migration.

## Warning
MAPAlloc is intended as a research tool. It may endanger the stability of your system and cause data loss. Use MAPAlloc at your own risk.
