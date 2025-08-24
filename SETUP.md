# CTinyWeb Setup Guide

This guide explains how to set up the development environment for CTinyWeb, including automated setup for AI agents like Cursor AI.

## Quick Setup (Automated)

### For Cursor AI Agent

Cursor AI Agent can automatically use these files for setup:

1. **`.cursor-setup.json`** - Main configuration file for Cursor AI
2. **`install_deps.sh`** - Automated dependency installation
3. **`run_tests.sh`** - Complete test suite runner

Simply tell Cursor AI Agent: *"Set up the development environment and run tests"* and it will:
- Read the `.cursor-setup.json` configuration
- Run `./install_deps.sh` to install dependencies
- Execute `./run_tests.sh` to build and test the project

### Manual Setup

If you prefer manual setup or are not using Cursor AI:

```bash
# 1. Install dependencies
./install_deps.sh

# 2. Build and test
./run_tests.sh
```

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