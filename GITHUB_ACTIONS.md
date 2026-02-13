# GitHub Actions CI/CD

This project is configured to build automatically on GitHub using GitHub Actions.

## Workflows

### Build Workflow (`.github/workflows/build.yml`)

**Triggers:**
- Push to branches: `main`, `master`, `develop`, `build-github`
- Pull requests to: `main`, `master`, `develop`
- Manual trigger via GitHub UI

**What it does:**
1. Sets up Ubuntu 22.04 build environment
2. Installs all required dependencies (Blake3, jsoncons, Flatbuffers, etc.)
3. Uses caching to speed up subsequent builds
4. Builds the `hpcore` executable using CMake
5. Uploads build artifacts (hpcore, hpws, hpfs binaries and license)

**Build artifacts** are available for download from the GitHub Actions run page for 30 days.

**Note:** Build artifacts include hpcore and helper binaries (hpws, hpfs) but not the Evernode license PDF, which should be added to the repository root if needed.

### Docker Workflow (`.github/workflows/docker.yml`)

**Triggers:**
- Push to branches: `main`, `master`
- Version tags (e.g., `v1.0.0`)
- Manual trigger via GitHub UI

**What it does:**
1. Builds the hpcore project
2. Creates a Docker image using the local-cluster Dockerfile
3. Pushes the image to GitHub Container Registry (ghcr.io)

**Image tags:**
- `latest` - Latest build from main/master
- Version tags (e.g., `v1.0.0`) - When pushing git tags
- Commit SHA - For specific commits

## Viewing Build Status

After pushing code to GitHub, you can:
1. Go to the **Actions** tab in your repository
2. Click on a workflow run to see build progress and logs
3. Download build artifacts from successful runs

## Running Workflows Manually

1. Go to the **Actions** tab
2. Select the workflow you want to run
3. Click "Run workflow"
4. Select the branch and click "Run workflow"

## Build Caching

The workflows use GitHub Actions caching to speed up builds by caching:
- CMake installation
- Third-party libraries (Blake3, jsoncons, Flatbuffers, etc.)

This significantly reduces build times after the first successful build.

## Build Compatibility Fixes

Several fixes were applied to ensure the project builds successfully with modern GCC compilers (GCC 11+) on Ubuntu 22.04:

### Code Fixes
1. **Array bounds fix** in `src/util/util.cpp` - Removed out-of-bounds array access in `realpath()` function
2. **Range-loop optimizations** in `src/unl.cpp` and `src/consensus.cpp` - Added references to prevent unnecessary copies in range-based for loops
3. **Flatbuffers compilation** - Disabled Flatbuffers tests to avoid compilation errors with strict warning flags

### Build System Changes
1. **CMakeLists.txt** - Modified post-build copy commands to use CMake's portable copy functions
2. **Optional file copying** - Made license file copying optional to prevent build failures when file is missing

These changes ensure `-Werror` (treat warnings as errors) doesn't cause build failures while maintaining code quality.

## Using Docker Images

Docker images are pushed to GitHub Container Registry (ghcr.io). To pull and use them:

```bash
# Pull latest image
docker pull ghcr.io/YOUR_USERNAME/hpcore:latest

# Pull specific version
docker pull ghcr.io/YOUR_USERNAME/hpcore:v1.0.0

# Run the container
docker run ghcr.io/YOUR_USERNAME/hpcore:latest
```

**Note:** Replace `YOUR_USERNAME` with your GitHub username or organization name.

## Troubleshooting

If builds fail:
1. Check the Actions tab for error logs
2. Verify all dependencies are correctly installed
3. Clear cache by updating the cache key in the workflow file (change `hpcore-libs-v1` to `hpcore-libs-v2`, etc.)
4. Ensure the repository has sufficient permissions to upload packages (for Docker workflow)

### Common Issues

**Missing files:** If `hpws` or `hpfs` binaries are missing from `test/bin/`, the build will skip copying them but continue successfully. Ensure these files are committed to the repository if needed.

**Compilation warnings as errors:** The project uses `-Werror` flag. If you encounter new warnings with newer compiler versions:
- Update the code to fix the warnings
- Or modify `CMakeLists.txt` to selectively disable specific warnings

**Cache issues:** If builds fail after dependency updates, clear the cache:
1. Go to repository Settings → Actions → Caches
2. Delete old caches
3. Re-run the workflow
