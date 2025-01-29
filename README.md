# govir - VirusTotal CLI Scanner

A command-line tool for scanning files using the VirusTotal API. This tool allows you to scan individual files, directories, or a combination of both for potential security threats.

## Features

- Scan individual files or entire directories recursively
- Support for multiple input paths
- Real-time status updates for each file
- Detailed reporting of scan results
- Rate-limited API calls to respect VirusTotal's service
- Support for files larger than 32MB using upload URLs
- Automatic comment addition with file path information

## Prerequisites

- Go 1.22 or later
- VirusTotal API key (get one from [VirusTotal](https://www.virustotal.com/))
- Make (optional, for using Makefile commands)
- Docker (optional, for containerized usage)

## Installation

### Building from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/govir.git
cd govir

# Build the binary
make build
```

### Using Docker

```bash
# Build the Docker image
make dockerize
```

## Configuration

The VirusTotal API key can be provided in three ways (in order of precedence):

1. Environment variable:
```bash
export VT_API_KEY=your-api-key
```

2. Configuration file (`config.yaml`):
```yaml
apikey: "your-virustotal-api-key"
```

## Usage

### Basic Usage

```bash
# Scan a single file
govir file.exe

# Scan multiple files
govir file1.exe file2.exe "file with spaces.exe"

# Scan a directory (recursively)
govir directory/

# Scan multiple directories and files
govir file1.exe directory1/ directory2/ file2.exe
```

### Using with Docker

```bash
# Using environment variable
VT_API_KEY=your-api-key docker-compose run govir file1.exe directory1/

# Using bind mount to scan local files
docker run -v $(pwd):/scan -w /scan -e VT_API_KEY=your-api-key govir file1.exe
```

### Example Output

```
file1.exe: pending
file1.exe: uploading
file1.exe: waiting for results
file1.exe: processing
file1.exe: clean

test1/malware.exe: pending
test1/malware.exe: uploading
test1/malware.exe: waiting for results
test1/malware.exe: processing
test1/malware.exe: issues reported
- Avira: HEUR/AGEN.1376865
- Cynet: Malicious (score: 99)
- WithSecure: Heuristic.HEUR/AGEN.1376865
```

## Development

### Project Structure

```
govir/
├── internal/
│   ├── config/      # Configuration handling
│   ├── scanner/     # File scanning logic
│   └── vtclient/    # VirusTotal API client
├── main.go          # CLI entry point
├── Dockerfile       # Docker build instructions
├── docker-compose.yml
├── Makefile
└── config.yaml      # Sample configuration
```

### Available Make Commands

```bash
# Build the binary
make build

# Run tests
make test

# Run linter
make lint

# Build Docker image
make dockerize

# Clean build artifacts
make clean

# Run all checks and build
make all
```

### Running Tests

```bash
# Run all tests with coverage
make test

# Run specific package tests
go test -v ./internal/scanner
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [VirusTotal API Documentation](https://docs.virustotal.com/reference/overview)
- [Go Standard Library](https://golang.org/pkg/)
