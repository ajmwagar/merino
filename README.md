```
                     _
 _ __ ___   ___ _ __(_)_ __   ___
| '_ ` _ \ / _ \ '__| | '_ \ / _ \
| | | | | |  __/ |  | | | | | (_) |
|_| |_| |_|\___|_|  |_|_| |_|\___/
```

**A SOCKS5 Proxy written in Rust**

## 🎁 Features

- Multi-threaded conneciton handler
- Lightwieght (around 6% CPU usage on a Pentium laptop)
- Standalone binary (no system dependencies)
- `1+ Gb/second` connection speeds (upload/download)
- Tunable logging (try `export RUST_LOG=merino=DEBUG`)
- `SOCKS5` Compatible Authentication methods:
  - No Authentication
  - Username & Password

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
# Start a SOCKS5 Proxy server listening on port 1080 without authentication
merino --no-auth

# Use username/password authentication and read users from users.csv
merino --users users.csv

# Display a help menu
merino --help 
```
