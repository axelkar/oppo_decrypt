# oppo_decrypt

## Oppo `.ofp` and OnePlus `.ops` firmware decrypter

Tools:

* `ofp_qc_decrypt`: Decrypts Qualcomm-based firmware with `.ofp` extension (Oppo)
* `ofp_mtk_decrypt`: Decrypts MediaTek-based firmware with `.ofp` extension (Oppo)
* `opscrypto`: Decrypts and re-encrypts firmware with `.ops` extension (OnePlus)
* `backdoor`: Enables hidden "readback" functionality in `MsmDownloadTool.exe`

## Installation

- Install Python >= 3.8

- Run the following commands in a terminal:

  ```sh
  # On Windows when you want to use the `backdoor` tool:
  pip install -e .[frida]
  # Everywhere else:
  pip install -e .
  ```

Windows, Linux and macOS are supported.

## Usage

### Extract Oppo `.ofp` file

```sh
oppo_decrypt ofp_qc_decrypt <myofp.ofp> <output directory>
oppo_decrypt ofp_mtk_decrypt <myofp.ofp> <output directory>
```

### Extract OnePlus `.ops` file

```sh
oppo_decrypt opscrypto decrypt <myops.ops>
```
File will be in a directory named `extract` next to the input file

### Repack OnePlus `.ops` file

```sh
oppo_decrypt opscrypto encrypt [path to directory with firmware]
```

### Enable readback mode (Windows-only)

Note: Launch the terminal with administrator privileges.

```sh
oppo_decrypt backdoor "MsmDownloadTool.exe"
```

### Merge super images

The `.ofp` may contain super firmware from multiple carriers, check the `super_map.csv.txt` outside `.ofp` first. You can use the `simg2img` tool (often packaged in Linux distributions as as [`android-tools`](https://github.com/nmeum/android-tools)) to merge them:

```sh
simg2img [super.0.xxxxxxxx.img] [super.1.xxxxxxxx.img] [super.1.xxxxxxxx.img] [filename to merge] # All split super imgs must be the same carrier
```

## License

Licensed under MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>).
