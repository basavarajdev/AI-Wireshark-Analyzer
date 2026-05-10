# Installation Without Virtual Environment

If you prefer not to use a virtual environment, here are your options:

## Option 1: Use `pipx` (Recommended Alternative)

**pipx** manages isolated environments automatically without you creating venvs manually:

```bash
# Install pipx if not already installed
sudo apt install pipx
pipx ensurepath

# This won't work directly for development projects, so see Option 2 or 3
```

## Option 2: Install with `--break-system-packages` Flag

⚠️ **Warning**: This installs packages system-wide and may conflict with system packages.

```bash
pip install -r requirements.txt --break-system-packages
```

Or install individually as needed:

```bash
pip install pyshark pandas numpy scikit-learn tensorflow --break-system-packages
pip install fastapi uvicorn click rich matplotlib seaborn --break-system-packages
pip install pyyaml loguru pytest --break-system-packages
```

## Option 3: Use System Package Manager (Recommended for System-Wide)

Install Python packages via apt (Ubuntu/Debian):

```bash
# Core dependencies
sudo apt install python3-pip python3-numpy python3-pandas python3-sklearn
sudo apt install python3-matplotlib python3-seaborn python3-yaml
sudo apt install python3-click python3-pytest tshark

# Then install remaining packages not in apt repos with --break-system-packages
pip install pyshark fastapi uvicorn rich loguru --break-system-packages
pip install tensorflow --break-system-packages  # Large package
```

## Option 4: User Installation (Recommended - No System Impact)

Install packages only for your user account (no sudo needed):

```bash
pip install -r requirements.txt --user
```

This installs to `~/.local/lib/python3.x/site-packages` and won't affect system packages.

## Option 5: Use Docker (Isolation Without Manual venv)

```bash
# Create Dockerfile
cat > Dockerfile <<'EOF'
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y tshark && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "src/api/rest.py"]
EOF

# Build and run
docker build -t ai-wireshark .
docker run -p 8000:8000 -v $(pwd)/data:/app/data ai-wireshark
```

## Recommended Approach

**For Development**: Use Option 4 (`--user` flag)

```bash
pip install -r requirements.txt --user
```

**For Production/Server**: Use Option 3 (system packages + selective pip)

**Why avoid `--break-system-packages`?**
- Can break system tools that depend on specific Python package versions
- OS updates might conflict with manually installed packages
- Harder to manage dependencies

## Verify Installation

After installation, verify packages are available:

```bash
python3 -c "import pyshark; import pandas; import sklearn; print('Packages OK')"
```

## Run the Project

After installation (any method), you can run:

```bash
# CLI
python3 src/api/cli.py info

# API Server
python3 src/api/rest.py

# Protocol Analyzers
python3 src/protocols/tcp_analyzer.py --input data/raw/sample.pcap
```

## Troubleshooting

### Command Not Found After `--user` Install

Add to your `~/.bashrc`:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Then reload: `source ~/.bashrc`

### Import Errors

Check where packages are installed:

```bash
pip list --user  # User packages
pip list         # System packages
```

### TShark/PyShark Issues

Ensure TShark is installed:

```bash
sudo apt install tshark
tshark --version
```

## Quick Start (No venv)

```bash
# Install with --user flag
cd /home/bidnal/Downloads/AI_wireshark
pip install -r requirements.txt --user

# Verify
python3 -c "import pyshark; print('Ready!')"

# Run analysis
python3 src/api/cli.py info
```

---

**Bottom Line**: You can absolutely use the project without creating a virtual environment. The `--user` flag is the safest option that doesn't require venv or system modifications.
