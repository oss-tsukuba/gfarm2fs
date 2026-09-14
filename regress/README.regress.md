# Regression tests for gfarm2fs

このディレクトリには、gfarm2fs と関連する回帰テスト用のスクリプトが
あります。各スクリプトが受け付ける引数や環境変数の詳細は、
各スクリプトの `--help` の出力を参照してください。

## スクリプトの概要

- `regress.sh` — テスト用 gfarm2fs をビルドし、マウント付きテストを
  1 回実行します。ASan、TSan、Valgrind の各モードにも対応します。
- `regress_gfarm2fs.py` — テストスクリプト本体。指定したディレクトリに対して、
  ファイル操作、並列 I/O、xattr 操作などを実行します。
- `run_regress_gfarm2fs_with_mount.sh` — gfarm2fs を起動してマウントし、
  マウントポイント上で `regress_gfarm2fs.py` を実行します。
  `regress.sh` から呼び出されます。
- `regress-matrix.sh` — regress.sh を通常実行、Memcheck、Helgrind、ASan、TSan
  のテストを順番に実行します。GitHub Actions からこれが実行されます。
- `build_gfarm2fs_for_test.sh` — 回帰テスト用の gfarm2fs をビルドします。
  `regress.sh` から呼び出されます。
- `run_regress_gfarm2fs_multi_python.sh` — pyenv を使って複数の Python
  バージョンで `regress_gfarm2fs.py` を実行します。
  `regress_gfarm2fs.py` 自体の動作確認用です。
  テスト対象ディレクトリを指定して使います。
- `test-fuse-passthrough_fh.sh` — libfuse の `passthrough_fh` サンプルを
  ビルド・マウントし、FUSE 実装に対してテストを実行します。
  FUSE 自体の一般的な挙動などの確認用です。
- `test-localfs.sh` — マウントを行わず、ローカルファイルシステム上で
  `regress_gfarm2fs.py` を実行します。
  `regress_gfarm2fs.py` 自体の動作確認用です。

## 実行例

テスト用バイナリのビルドから実行まで行う:

```sh
./regress.sh
```

テスト用バイナリを ASan 付きでビルドして実行する:

```sh
./regress.sh --asan
```

5 種類の実行モードをまとめて実行する:

```sh
./regress-matrix.sh
...
### この出力が最後に表示されれば異常無し ###
[INFO]: regress-matrix: No tool warnings detected
[ OK ]: regress-matrix: All modes passed
```

FUSE2 を使ってビルド・テスト:

```sh
# (RHEL および派生)   sudo dnf install fuse fuse-devel
# (Debian および派生) sudo apt install fuse libfuse-dev
CONFIGURE_ARGS="--with-gfarm=/usr/local --with-fuse2" ./regress.sh
```

## 環境変数

指定可能な環境変数はスクリプトごとに異なります。利用可能な変数と既定値
は、各スクリプトの `--help` の出力およびスクリプト内の `Environment:`
欄を参照してください。

スクリプトは別のスクリプトを呼び出す構成になっています。上位の
スクリプトで設定した環境変数は子プロセスに継承されるため、呼び出し元
だけでなく、そこから呼び出される末端のスクリプトにも効果があります。
例えば、`regress.sh` から `run_regress_gfarm2fs_with_mount.sh` と
`regress_gfarm2fs.py` が呼び出されるため、`REGRESS_ARGS` や
`GFARM2FS_CMD` はその実行全体に適用されます。

例:

```sh
REGRESS_ARGS='--gfarm2fs --gfarmized --xattr --tests symlink,hardlink' \
  GFARM2FS_TESTDIR=/tmp \
  ./regress/regress.sh
```
