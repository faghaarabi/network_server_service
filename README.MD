# BIG Chat Protocol v0.3
## Building:

**(IF ON MACOS ARM64)**
Run the following in your terminal before running any of the build scripts:

```{bash}
export CPATH=/opt/homebrew/include
export LIBRARY_PATH=/opt/homebrew/lib
export CMAKE_PREFIX_PATH=/opt/homebrew
```

### 1. Generate CMakeLists.txt from files.txt
```{bash}
./generate-cmakelists.sh
```
### 2. Check for supported compilers
```{bash}
./check-compilers.sh
```
### 3. Generate compiler-specific flags
```{bash}
./generate-flags.sh
```
### 4. Check that your environment has all the required tools
```{bash}
./check-env.sh -c <COMPILER>
```

### 5. Configure CMake and build the environment
```{bash}
./change-compiler.sh -c <COMPILER>
```

### 6. Executed the build
```{bash}
./build.sh
```