# Interclus

[![ci](https://github.com/HiChat-fog/Interclus/actions/workflows/ci.yml/badge.svg)](https://github.com/HiChat-fog/Interclus/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

[English](README.md) | 简体中文

*被 RISC-V PMP 隔离的 eBPF 解释器。*

![architecture](docs/architecture.png)

在一颗没有 MMU 的 CH32V307（RV32IMAFC）上，eBPF 解释器以非特权身份运行在
PMP 圈出的舱室里。机器模式的 supervisor 负责武装边界、调度舱室，并把捕获、
取证、恢复连成一个闭环：每一次非法访问都记下 `mcause` 和 `mtval`，随后被
跳过或改道，监视器照常运行。

**不需要硬件。** 完整的容量扫描在 QEMU 里就能跑：

    bash qemu/build_qemu.sh
    qemu-system-riscv32 -M virt -bios none -kernel build/fw_qemu.elf -nographic

八档机群规模（N=8..64）走与板子相同的四相位流水线：eBPF 过滤、网格筛查、
native C 参考过滤器，以及五步攻击谱。每一档都打印证据：

    verdicts: 1 1 0 2 3 4
    insns:    15 12 5 12 13 15
    alerts:  board=4 mirror=4
    attack:  n=4 mtval: 0x80200200 0x80200080 0x80200200 0x80100000
    integrity: verdicts=1 checksum=1 own=1 native=1 proof=1
    == MATCH ==

    ...

    == SWEEP 8/8 MATCH ==

整条扫描线的告警数是 0, 0, 3, 4, 10, 15, 19, 26，与板子逐点一致（见下文）。

## 能在这里看到什么

- 真实 MCU 上的 PMP 分舱：NAPOT 区域、deny-all 补位项，以及实测到的厂商
  怪癖（四个可用表项、unmatched-allow、错位的 `mtvec` 会破坏 trap 递送）
- 32 位核上具备完整 64 位语义的 eBPF 子集解释器
- 一个对隔离发起攻击、被当场捕获的探针，取证精确到地址
- 一份固件，两个目标：真实硅片与 QEMU，经 `core/platform.h` 切换
- 启动时装载：外部字节码过预检门后替换编译期策略（见下文）

## 目录结构

    core/                 contract.h、eBPF 解释器、helpers、trap 捕获、地址图
    modules/              supervisor、monitor、attacker 探针、策略、板上地址
    qemu/                 QEMU 目标：引导、机群 mailbox、证据报告
    tests/                宿主测试
    tools/                机群注入、程序装载、宿主侧镜像比对
    docs/                 架构图
    reference/            记录结果所用的固件镜像
    build.sh              板级固件
    qemu/build_qemu.sh    QEMU 固件

## 宿主测试

    gcc -fsanitize=address,undefined -ffreestanding -o t tests/test_host.c core/ebpf.c core/helpers.c
    ./t

66 个用例必须全过。同一个 C99 解释器分别编译到 x86-64 和 RV32，判决与指令
数逐位一致。

## 在板子上运行

硬件：CH32V307VCT6 板 + WCH-LinkE 调试器。

    ./build.sh                            # -> build/fw_pmp.bin
    wlink flash -e build/fw_pmp.bin
    python3 tools/inject_swarm.py 32 --seed 7

    swarm N=32 (seed=7)  host alerts=4  board alerts=4
    RESULT: MATCH ✅

规模（8 到 64，mailbox 满容量）和种子都可以随便换。

## 启动时装载程序

开机时 supervisor 会检查程序区：一个 `PROG` 头加裸字节码。字节先过描述符
门和静态预检，才落进监视舱的槽位；被拒的程序退回编译期策略，原因记录在
STATUS 里。

    python3 tools/load_prog.py          # 板上（WCH-LinkE 在位）：判决翻转
    python3 tools/load_prog.py --bad    # 超长计数：退回内置策略，记原因码
    qemu-system-riscv32 -M virt -bios none -kernel build/fw_load.elf -nographic

QEMU 那条跑的是同一条装载路径，收尾打印 `== LOAD PASS ==`。

## PMP 语义探针

专门的探针固件测量这颗核的 PMP 行为，把原始证据倾倒进 SRAM：

    wlink flash -e build/pmp_probe.bin
    wlink dump 0x20000100 400     # CSR 回读、fault 日志、U-mode 标记

最后一段按设计会挂住（错位 `mtvec` 的 trap 测试）；之后重新烧
`build/fw_pmp.bin`。

## 路线图

- UART 数据通道，取代调试器 mailbox
- native 模块装载：PMP 舱室分时复用
- 支持其他带 PMP 的 RISC-V MCU

## 工具链

| 用途 | 需要 |
| --- | --- |
| 宿主测试 | gcc（或 clang） |
| 板级固件 | clang riscv32 target、`lld` 或 rust-lld、`riscv64-unknown-elf-objcopy`、`wlink` |
| QEMU 固件 | clang riscv32 target、`lld` 或 rust-lld、`qemu-system-riscv32` |
| 注入/装载工具 | python3 |

## 许可

MIT
