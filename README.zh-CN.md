# Interclus

[![ci](https://github.com/HiChat-fog/Interclus/actions/workflows/ci.yml/badge.svg)](https://github.com/HiChat-fog/Interclus/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

[English](README.md) | 简体中文

> *被 RISC-V PMP 圈住的 eBPF 解释器。*

一颗没有 MMU 的 CH32V307（RV32IMAFC）上，eBPF 解释器以非特权身份运行在 PMP 舱室里。
机器模式 supervisor 负责武装边界、调度舱室，并在舱室第一次非法访问时留下证据：
`mcause` 与 `mtval` 进入取证环，寄存器现场存入 TCB，然后逐出。调度继续。

舱室由区域表驱动：每个舱室持有一张虚拟区域表（VRT），四个 PMP 表项是它的缓存。两行
常驻（sram、text），一个槽在首次故障时换入其余被覆盖的行并重试原指令，一个无权限项
兜住剩下的地址空间。表外的访问或权限不足，走取证路径。

## 快速开始（无硬件）

```bash
bash qemu/build_qemu.sh
qemu-system-riscv32 -M virt -bios none -kernel build/fw_qemu.elf -nographic
```

八档机群（N=8..64）跑与板子相同的四相位流水线：eBPF 过滤、网格筛查、native-C 参考
过滤、攻击谱。

```text
verdicts: 1 1 0 2 3 4
alerts:  board=4 mirror=4
attack:  n=5 mtval: 0x80200200 0x80200080 0x80200200 0x80100000 0x80100000
integrity: verdicts=1 checksum=1 own=1 native=1 proof=1 sv=1 nat2=1 swaps=1
== SWEEP 8/8 MATCH ==
```

整条扫描的告警数是 0, 0, 3, 4, 10, 15, 19, 26，板子逐点复现。`swaps=1` 是 map 行在
筛查阶段的一次换入。

## 舱室引擎

| 表项 | 职责 |
| --- | --- |
| 0 | 常驻 sram 行，R/W |
| 1 | 常驻 text 行，R/X |
| 2 | 换入槽，每次填入一条 NAPOT 地址 |
| 3 | 无权限兜底项，永远武装 |

武装舱室只写两行常驻行和一个在挂载时拼好的 cfg 字。trap 入口对 load、store、fetch
故障分类：VRT 命中且权限足够时，写 `pmpaddr2`、fence、带上常驻字节写 `pmpcfg0`、
fence、按原 `mepc` 返回；其余情况进入取证路径。native 两个槽各是一个独立域。

eBPF map 放在 monitor box 之外，单独占一行 VRT；验证器从这一行取 helper 权限
（helper 1 需要 R，helper 2 需要 W），启动门拒绝与挂载行不一致的策略。

| 路径 | QEMU 指令数 | CH32V307 STK tick |
| --- | --- | --- |
| 武装舱室 | 26 | 5-6 |
| 换入 load | 88 | 45 |
| 换入 store | 91 | 45-46 |
| 换入 fetch | 103 | 48-49 |

一个 tick 是 8 个 HCLK 周期；换入是端到端口径。

## 目录结构

```text
core/          contract、eBPF 解释器、helpers、trap 捕获、地址图
core/pmp/      虚拟区域表、换入引擎、V4F 端口
modules/       supervisor、monitor、attacker、策略
qemu/          QEMU 目标、证据报告、换入演练
tests/         宿主测试：解释器、引擎、验证器
tools/         机群注入、程序装载、板级审计
docs/          架构图
reference/     记录结果所用的固件镜像
```

## 验证

| 关卡 | 位置 | 覆盖 |
| --- | --- | --- |
| 宿主 | x86-64 上 91 项检查 | 判定与指令数逐位一致、引擎不变量、区域门 |
| QEMU | 完整调度，CI | 扫描、装载、热替换、通道、遥测、持久化、信任、预算、换入演练 |
| 板级 | CH32V307 + WCH-LinkE | 记录数字来自硅片 |

```bash
gcc -O2 -ffreestanding -o t tests/test_host.c core/ebpf.c core/helpers.c core/frame.c && ./t
gcc -O2 -ffreestanding -o p tests/test_pmp.c core/pmp/icp.c && ./p
gcc -O2 -ffreestanding -o v tests/test_verifier.c core/loader.c && ./v
qemu-system-riscv32 -M virt -bios none -kernel build/fw_fill.elf -nographic
```

换入演练覆盖三种操作的计时、两行溢出区之间的 200 次换入抖动，以及三组违规。

### 板子上

```bash
./build.sh
wlink flash -e build/fw_pmp.bin
python3 tools/inject_swarm.py 32 --seed 7    # host alerts=4  board alerts=4
python3 tools/pmpa_board.py                  # PMP 围栏扫描
```

### 装载与通道

程序区的 `PROG` 镜像、控制台帧、运行时帧都过同一组门。`build/pmp_probe.bin` 把 CSR
回读与故障日志倒进 SRAM，最后一阶段按设计挂起，之后刷回 `build/fw_pmp.bin`。

```bash
python3 tools/load_prog.py
python3 tools/uart_frame.py | qemu-system-riscv32 -M virt -bios none -kernel build/fw_urx.elf -display none -serial stdio -monitor none
python3 tools/chan_qemu.py
python3 tools/uart_data.py 24
```

## 路线图

- [x] 运行时通道：数据、eBPF、native 模块帧
- [x] 舱室：时间片复用的 PMP 盒
- [x] VRT 引擎：常驻行、单换入槽、故障时填入
- [x] 区域感知验证器与 map 行
- [ ] 支持更多带 PMP 的 RISC-V MCU

## 工具链

| 用途 | 需要 |
| --- | --- |
| 宿主测试 | gcc 或 clang |
| 板级 | clang riscv32、lld、`riscv64-unknown-elf-objcopy`、`wlink` |
| QEMU | clang riscv32、lld、`qemu-system-riscv32` |

## License

MIT
