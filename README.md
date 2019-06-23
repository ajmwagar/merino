```
                     _
 _ __ ___   ___ _ __(_)_ __   ___
| '_ ` _ \ / _ \ '__| | '_ \ / _ \
| | | | | |  __/ |  | | | | | (_) |
|_| |_| |_|\___|_|  |_|_| |_|\___/
```

**A `SOCKS5` Proxy server written in Rust**

## 🎁 Features

- Multi-threaded connection handler
- Lightweight (Less than 0.6% CPU usage while surfing the web/streaming YouTube)
- Standalone binary (no system dependencies)
- `1+ Gb/second` connection speeds (**On Gigabit LAN network over ethernet. Results may vary!**)
- Tunable logging (try `export RUST_LOG=merino=DEBUG`)
- `SOCKS5` Compatible Authentication methods:
  - `NoAuth`
  - Username & Password
  - `GSSAPI` Coming Soon!

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

# 🚥 Roadmap

- [x] IPV6 Support
- [ ] `SOCKS5` Authentication Methods
  - [x] `NOAUTH` 
  - [x] `USERPASS`
  - [ ] `GSSAPI` Coming Soon!
- [ ] Custom plugin/middleware support
- [ ] `SOCKS5` Commands
  - [x] `CONNECT`
  - [ ] `BIND`
  - [ ] `ASSOCIATE` 
- [ ] Benchmarks & Unit tests
- [ ] [Actix](https://github.com/actix-rs/actix) based backend
- [ ] `SOCKS4`/`SOCKS4a` Support
