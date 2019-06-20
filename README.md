```
                     _
 _ __ ___   ___ _ __(_)_ __   ___
| '_ ` _ \ / _ \ '__| | '_ \ / _ \
| | | | | |  __/ |  | | | | | (_) |
|_| |_| |_|\___|_|  |_|_| |_|\___/
```

**A SOCKS5 Proxy written in Rust**

## 🎁 Features

- Multi-threading 
- Standalone binary (no system dependencies)
- `100+ Mb/second` connection speeds (upload/download)
- Tunable logging (try `export RUST_LOG=merino=DEBUG`)
- `SOCKS5` Compatible Authentication methods:
  - No Authentication
  - User name & Password Auth

## 📦 Installation & 🏃 Usage

### Installation

```bash
cargo install merino
```

OR

```bash
git clone https://github.com/ajmwagar/merino
cd merino
cargo install --path .
```

### Usage

```bash
merino # Start a SOCKS5 Proxy server listening on port 1080

merino -p 8080 # Set the port to 8080

merino --help # Displays a help menu
```
