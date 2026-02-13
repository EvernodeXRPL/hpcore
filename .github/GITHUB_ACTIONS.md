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
3. Clear cache by updating the cache key in the workflow file
4. Ensure the repository has sufficient permissions to upload packages (for Docker workflow)
