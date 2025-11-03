# CTinyWeb Setup Guide

The project now defaults to a gossip-first runtime. Blockchain + PBFT remain available as an optional feature under `src/features/blockchain`.

## 1. Dependencies

```bash
./install_deps.sh
```

This installs toolchains (gcc, cmake, make) and required libraries (libsodium, sqlite3, cJSON, libmicrohttpd, etc.).

## 2. Configure + Build

```bash
cmake -S . -B build
cmake --build build --target tinyweb tinyweb_tests
```

This produces the gossip node (`tinyweb`) and the default gossip test binary (`tinyweb_tests`).

## 3. Run Gossip Tests

```bash
cd build
ctest --output-on-failure
```

By default the test runner executes encryption, signing, and gossip-related suites. Use `ctest -N` to view available test names.

## 4. Optional: Build PBFT Feature Targets

```bash
cmake --build build --target tinyweb_pbft tinyweb_pbft_tests init_tool

cd build
ctest -R "^Pbft" --output-on-failure
```

PBFT executables and tests are isolated in `src/features/blockchain`. Building these targets is opt-in and does not affect the gossip executable.

## Reference Scripts

- `install_deps.sh` – installs system packages listed in `requirements-apt.txt`
- `run_tests.sh` – legacy helper that still runs the gossip pipeline (`cmake`, build, `ctest`)
- `.cursor-setup.json` – configuration for the Cursor AI agent (dependency install + build + test commands)

## Build Matrix

| Target | Description |
|--------|-------------|
| `tinyweb` | Gossip UDP + HTTP node |
| `tinyweb_tests` | Gossip unit/integration tests |
| `tinyweb_pbft` | PBFT blockchain node (optional) |
| `tinyweb_pbft_tests` | PBFT-specific tests (optional) |
| `init_tool` | Blockchain initialisation helper |

## Testing Cheat Sheet

```bash
# Gossip-only test run
cmake --build build --target tinyweb_tests
ctest --output-on-failure

# PBFT feature test run
cmake --build build --target tinyweb_pbft_tests
ctest -R "^Pbft" --output-on-failure
```

## Continuous Integration Snippet

```yaml
- name: Install deps
  run: ./install_deps.sh

- name: Build gossip node
  run: |
    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build --target tinyweb tinyweb_tests

- name: Run gossip tests
  run: |
    cd build
    ctest --output-on-failure

- name: Build PBFT feature (optional)
  if: ${{ inputs.build_pbft }}
  run: |
    cmake --build build --target tinyweb_pbft tinyweb_pbft_tests init_tool
    cd build
    ctest -R "^Pbft" --output-on-failure
```

## Project Layout

```
CTinyWeb/
├── src/
│   ├── main.c                         # Gossip entry point
│   ├── packages/
│   │   ├── comm/gossip/               # UDP transport
│   │   ├── comm/gossipApi.*           # HTTP API
│   │   ├── sql/gossip_store.*         # Gossip persistence
│   │   └── transactions/              # Shared transaction types
│   └── features/blockchain/           # Optional PBFT modules & tests
├── CMakeLists.txt                     # Gossip-first build configuration
├── src/features/blockchain/CMakeLists.txt  # Feature-only targets
├── install_deps.sh
├── requirements-apt.txt
└── SETUP.md
```

## Troubleshooting

- **Missing packages** – rerun `./install_deps.sh`
- **Build errors** – run `cmake --build build --clean-first ...`
- **ctest failures** – rerun with `--output-on-failure` or `-V` for verbose logs
- **PBFT schema issues** – remember that the default gossip runtime uses `db_init_gossip`; PBFT targets run the full schema migration when they start.

## Prerequisites Files Explained

### 1. `install_deps.sh` 
**Purpose**: Installs all system dependencies
```bash
./install_deps.sh
```
- Updates package lists
- Installs build tools (cmake, make, gcc)
- Installs required libraries (libsodium, sqlite3, cjson, etc.)
- Installs optional development tools (valgrind, gdb)

### 2. `requirements-apt.txt`
**Purpose**: Simple list of APT packages needed
```bash
# Install packages from file
sudo apt-get install $(cat requirements-apt.txt | grep -v '^#' | tr '\n' ' ')
```

### 3. `run_tests.sh`
**Purpose**: Complete build and test pipeline
```bash
./run_tests.sh
```
- Cleans previous builds
- Runs `cmake . && make`
- Verifies build artifacts
- Executes test suite (`./tinyweb_tests`)
- Reports success/failure

### 4. `.cursor-setup.json`
**Purpose**: Cursor AI Agent configuration
- Defines project structure
- Specifies build system (CMake)
- Lists dependencies
- Configures test execution
- Enables pre-commit testing

## System Requirements

### Operating System
- **Primary**: Ubuntu 20.04+ / Debian 11+
- **Tested**: Linux with APT package manager
- **May work**: Other Linux distributions (with package name adjustments)

### Required Packages
```
build-essential cmake make gcc pkg-config
libsodium-dev libsqlite3-dev libcjson-dev
libcurl4-openssl-dev libmicrohttpd-dev
liblz4-dev libp11-kit-dev libssl-dev
```

### Optional Development Tools
```
valgrind gdb strace ltrace
```

## Build Process

The standard build process is:
```bash
cd CTinyWeb
cmake .           # Configure build
make              # Compile
./tinyweb_tests   # Run tests
```

## Testing

### Running Tests
```bash
# Quick test run
./tinyweb_tests

# Full test pipeline (recommended)
./run_tests.sh
```

### Test Suites Included
- ✅ Encryption tests
- ✅ Signing tests  
- ✅ Blockchain tests
- ✅ Database tests
- ✅ Network initialization tests
- ✅ HTTP client tests
- ✅ Mongoose tests

## For AI Agents and CI/CD

### Cursor AI Agent Integration

1. **Automatic Setup**: Cursor AI will read `.cursor-setup.json` and automatically:
   - Install dependencies via `install_deps.sh`
   - Build the project via CMake
   - Run tests via `run_tests.sh`

2. **Pre-commit Testing**: Configure Cursor AI to run tests before commits:
   ```json
   "pre_commit": {
     "run_tests": true,
     "scripts": ["./run_tests.sh"]
   }
   ```

### GitHub Actions / CI/CD

```yaml
# Example GitHub Actions workflow
- name: Setup CTinyWeb
  run: ./install_deps.sh

- name: Test CTinyWeb  
  run: ./run_tests.sh
```

### Custom AI Agents

Your AI agent can parse `.cursor-setup.json` to understand:
- Required system packages
- Build commands
- Test execution
- Success criteria

## Troubleshooting

### Common Issues

1. **Missing Dependencies**
   ```bash
   # Re-run dependency installation
   ./install_deps.sh
   ```

2. **Build Failures**
   ```bash
   # Clean and rebuild
   make clean
   cmake .
   make
   ```

3. **Test Failures**
   ```bash
   # Run tests with verbose output
   ./tinyweb_tests
   ```

### Package Manager Issues

If you're not using APT, manually install equivalent packages:
- **Fedora/RHEL**: Use `dnf`/`yum` with RPM package names
- **Arch**: Use `pacman` with Arch package names
- **macOS**: Use `brew` with Homebrew formulas

## Project Structure

```
CTinyWeb/
├── .cursor-setup.json     # Cursor AI configuration
├── install_deps.sh        # Dependency installer
├── run_tests.sh          # Test runner
├── requirements-apt.txt   # Package list
├── SETUP.md              # This file
├── CMakeLists.txt        # Build configuration
├── src/                  # Source code
└── tests/                # Test files
```

## Next Steps

After setup:
1. ✅ Dependencies installed
2. ✅ Project builds successfully  
3. ✅ All tests pass
4. 🚀 **Ready for development!**

Try running the main application:
```bash
./tinyweb
```

Or initialize a test network:
```bash
./init_tool
``` 