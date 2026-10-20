# idare2

> radare2 的命令行与输出体验，IDA Pro 的分析引擎。

`idare2` 用 [IDA Nexus](https://github.com/HexRaysSA/ida-nexus) 驱动 IDA 数据库，
提供一套与 radare2 **语法、输出、交互一致**的逆向工具。反汇编、交叉引用、类型、
字符串全部来自 IDB 与 Hex-Rays，因此 `idare2` 可以和 IDA GUI **同时操作同一个数据库**。

## 安装

需要 IDA 9.1+（含 idalib）、Python 3.11+。

```bash
# idalib 的 Python 模块（一次性；<IDA> 指你的 IDA 安装目录）
pip install <IDA>/idalib/python/idapro*.whl
python <IDA>/py-activate-idalib.py -d <IDA>

# idare2
uv venv --python 3.12
uv pip install -e '.[test]'
```

装好后 `idare2`（别名 `ir2`）就在虚拟环境的 `PATH` 里。

## 用法

```bash
idare2 firmware.bin                      # 交互式，提示符 [0x00015e10]>
idare2 -qc 's main; pd 10' firmware.bin  # 批处理
idare2 -qc 'pd 10' firmware.bin | grep call
idare2 --idb saved.i64 -qc 'afl~main'    # 直接用现成的 IDB
idare2 --attach 12345-a1b2c3 -qc 'axt'   # 附着到已打开的 IDA GUI
idare2 -L                                # 列出在线的数据库
```

真实输出（一个 ARM32 固件 `httpd`）：

```
[0x00015e10]> s main
[0x00015e10]> pd 6
┌ 2036: int __fastcall(int argc, const char **argv, const char **envp)
│           0x00015e10      10482de9       PUSH {R4,R11,LR}
│           0x00015e14      08b08de2       ADD R11, SP, #8
│           0x00015e18      fcd04de2       SUB SP, SP, #0xFC
│           0x00015e1c      f8000be5       STR R0, [R11,#-8+argc]
│           0x00015e20      fc100be5       STR R1, [R11,#-8+argv]
└           0x00015e24      00210be5       STR R2, [R11,#-8+envp]

[0x00015e10]> px 16
- offset -  1011 1213 1415 1617 1819 1A1B 1C1D 1E1F  0123456789ABCDEF
0x00015e10  1048 2de9 08b0 8de2 fcd0 4de2 f800 0be5  .H-.......M.....

[0x00015e10]> afl~main
0x0000f1f0     2     12 __uClibc_main
0x00015e10    75   2036 main
0x0003fd6c    21   1124 old_main_init

[0x00015e10]> axt
_start 0xf3cc [DATA:r--] LDR R0, =main
(nofunc) 0xf3e0 [DATA:r--] DCD main
```

## 已实现

| 族 | 命令 |
|---|---|
| 定位 | `s` `s+` `s-` `s++` `s--` `sf` `sF` `sb` `sn` `so` `sp` `s=`（seek 历史）`s:` `s*` |
| 反汇编 | `pd` `pD` `pdf` `pdb` `pdr` `pi` `pdl` `pdq` `pdj` `pdc`（Hex-Rays） |
| 内存 | `px` `pxw` `pxq` `pxd` `pxu` `p8` `pr` `pc` `ps` `psw` `pv` `ph` `pwd` |
| 信息 | `iI` `ij` `iS` `ii` `is` `iz` `ie` `iE`（含 `j` 后缀） |
| 分析 | `aa` `aaa` `af` `afr` `afn` `afi` `afl` `afb` `afc` `afC` `ab` `axt` `axf` `axj` |
| 搜索 | `/` `/x` `/v` `/r` `//` `/+`（含 `j` 后缀） |
| 写操作 | `w` `wq` `wx` `w0` `wd` `wf` `wi` `w6` `wc` `wc+` `wc-` `u` `U` |
| 元信息 | `C` `Cj` `C.` `CC` `CCr` `CCu` `CC.` `CC-` `C-` `Cd` `Cd.` |
| 类型 | `t` `tj` `t*` `ts` `tp` `tc` `tt` `t-` `td` `te` `dt` |
| 标志 | `f` `f*` `f,` `f-` `f?`（默认写回 IDB，`e ida.flags.write=false` 可关） |
| 会话 | `$` 别名、`S` 脚本、`Ps`/`Po`/`P-`/`Pj`/`P` 工程、`y`/`yy`/`yx`/`yt`/`yf` 剪贴板、`cc`/`c1` 块比较 |
| 其它 | `?` `?v` `?x` `?b` `?o` `?u` `?e` `?$` `b` `e` `q` `L` `_` |

操作符：`;`、`@ addr`、`@!n`、`@{from to}`、`@@f` `@@i` `@@b` `@@=` `@@s:`、`~`（完整 r2 语义）、
`|`、`>`、`>>`、`!`、`.`、重复前缀 `3pd`、裸数字定位。

多语句出错时**不中断**：`idare2 -qc '?e one; zzz; ?e three'` 会打印 `one`、把 `unknown command 'zzz'`
写到 stderr、再打印 `three`（`zzz` 只是随便一个 idare2 里不存在的命令）；
批量模式只要有一条失败，退出码就是 1。

## 与 r2 的差异

设计上刻意与 r2 对齐，但底层引擎不同，差异是必然的。最常见的几条：

- **`aa` 通常是 no-op**：IDA 打开数据库时已经分析完了；`afl` 不需要先跑 `aa`。
- **`asm.arch` / `asm.bits` 只读**：架构由 IDB 决定，不能中途切换；用 `-a`/`-b` 在**新建**时指定。
- **默认只读**，`-w` 才允许写。
- **`w` 单独使用 = 保存 IDB**。
- **`f name [sz] [addr]` 会写回 IDB**（因为是共享数据库），可用 `e ida.flags.write=false` 关闭。
  参数顺序与 r2 相同：size 在前、地址在后；`f zz 0x40000` 是「大小 0x40000、落在当前 seek」。
- **`-j` 会让有 `j` 形式的命令默认输出 JSON**（`pd`、`afl`、`afi`、`iI`、`iz`、`C`、`t`、`b`、`/` 等）；
  没有 `j` 形式的命令（如 `px`、`f`、`s`）不受影响。
- **`wa`（汇编）在 ARM 上不可用**：IDA 9.5 的 ARM 处理器模块没有注册汇编器
  （`ida_idp.ph.asm is None`）。idare2 会明确报错；r2 用 keystone 覆盖了这块。
- **CLI 参数分三档**：21 个实现、12 个接受但忽略、7 个明确拒绝（`-d` 等会静默给出错误结果的）。

## 开发

```bash
uv run pytest                          # 单元测试（离线，~1 秒）
uv run pytest -m real_ida              # 真实 IDA 集成测试
uv run pytest -m parity                # 与 radare2 的输出一致性测试
uv run ruff check src tests
```

集成与一致性测试会先把目标复制到临时目录——**IDA 只要打开过 `.i64`，关闭时就会重写它**，
即使没有做任何修改。

## License

MIT
