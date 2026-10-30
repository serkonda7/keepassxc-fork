# AGENTS.md
## Build
Use unity (jumbo) builds and `-O1` optimization for development:
```sh
cmake -S . -B build-unity -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DKEEPASSXC_BUILD_TYPE=Snapshot -DKPXC_FEATURE_DOCS=OFF -DWITH_TESTS=OFF \
  -DCMAKE_CXX_FLAGS_RELEASE="-O1 -DNDEBUG" \
  -DCMAKE_UNITY_BUILD=ON -DCMAKE_UNITY_BUILD_BATCH_SIZE=8
```

Notes:
- Anonymous-namespace classes/functions must have unique names across the whole project: when two translation units in the same directory both define a same-named name, unity merges them and the compile fails. Rename with a file/class-specific prefix (see `ReportsWidgetHealthcheck.cpp`/`ReportsWidgetHibp.cpp` and `ProtonPassReader.cpp` for examples).
- `windows.h` defines `MessageBox` as a macro which can leak into unity TUs before `MessageBox.h` is included; `src/gui/MessageBox.h` undefs it, keep that in place.
- `CMAKE_UNITY_BUILD_BATCH_SIZE=8` caps the per-unit size (memory/latency balance). Batch size affects which files collide — changes must hold for the batch size in use.
