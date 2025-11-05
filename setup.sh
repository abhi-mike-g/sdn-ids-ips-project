#!/bin/bash

#############################################
# SDN-NIDPS Project Setup Script
# Automates installation and configuration
#############################################

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions for colored output
print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

# Check OS
check_os() {
    if [[ "$OSTYPE" != "linux-gnu"* ]]; then
        print_error "This script only supports Linux"
        exit 1
    fi
    
    if ! command -v lsb_release &> /dev/null; then
        print_error "lsb_release not found"
        exit 1
    fi
    
    OS_VERSION=$(lsb_release -sr)
    print_success "Running on Linux (Ubuntu $OS_VERSION)"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_warning "This script should be run with sudo for best results"
        print_warning "Some operations will require elevated privileges"
    fi
}

# Install system dependencies
install_dependencies() {
    print_header "Installing System Dependencies"
    
    print_warning "Updating package manager..."
    apt-get update > /dev/null 2>&1
    
    local packages=(
        "python3"
        "python3-pip"
        "python3-dev"
        "build-essential"
        "git"
        "wget"
        "curl"
        "nano"
        "net-tools"
        "tcpdump"
        "iperf3"
        "openvswitch-switch"
        "openvswitch-common"
        "suricata"
        "suricata-update"
        "mininet"
        "iperf"
    )
    
    for package in "${packages[@]}"; do
        if dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q "ok installed"; then
            print_success "$package already installed"
        else
            print_warning "Installing $package..."
            apt-get install -y "$package" > /dev/null 2>&1
            print_success "$package installed"
        fi
    done
}

# Install Python dependencies
install_python_deps() {
    print_header "Installing Python Dependencies"
    
    if [ ! -f "requirements.txt" ]; then
        print_error "requirements.txt not found!"
        exit 1
    fi
    
    pip3 install --upgrade pip setuptools wheel > /dev/null 2>&1
    print_success "pip upgraded"
    
    pip3 install -r requirements.txt
    print_success "Python dependencies installed"
}

# Create directory structure
create_directories() {
    print_header "Creating Directory Structure"
    
    local dirs=(
        "logs"
        "models"
        "config"
        "database"
        "threat_model"
        "src/controller"
        "src/detection/rules"
        "src/network"
        "src/database"
        "src/dashboard/static/css"
        "src/dashboard/static/js"
        "src/dashboard/static/lib"
        "src/dashboard/templates"
        "src/attacks"
        "src/monitoring"
        "src/utils"
    )
    
    for dir in "${dirs[@]}"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
            print_success "Created $dir"
        else
            print_success "$dir already exists"
        fi
    done
}

# Initialize database
init_database() {
    print_header "Initializing Database"
    
    python3 << 'EOF'
try:
    from src.database.database import db
    print("✓ Database initialized successfully")
except Exception as e:
    print(f"✗ Database initialization failed: {e}")
    exit(1)
EOF
}

# Configure Suricata
configure_suricata() {
    print_header "Configuring Suricata"
    
    if [ -f "config/suricata.yaml" ]; then
        sudo cp config/suricata.yaml /etc/suricata/suricata.yaml 2>/dev/null
        print_success "Suricata configuration copied"
    fi
    
    if command -v suricata-update &> /dev/null; then
        print_warning "Updating Suricata rules..."
        sudo suricata-update > /dev/null 2>&1
        print_success "Suricata rules updated"
    fi
}

# Create necessary files
create_files() {
    print_header "Creating Necessary Files"
    
    # Create empty log files
    touch logs/nidps.log
    touch logs/controller.log
    touch logs/dashboard.log
    chmod 666 logs/*.log
    print_success "Log files created"
    
    # Create configuration if not exists
    if [ ! -f "config/controller_config.json" ]; then
        cat > config/controller_config.json << 'EOF'
{
  "controller": {
    "host": "0.0.0.0",
    "port": 6653
  },
  "database": {
    "url": "sqlite:///logs/nidps.db"
  },
  "suricata": {
    "eve_log": "/var/log/suricata/eve.json"
  },
  "dashboard": {
    "host": "0.0.0.0",
    "port": 5000,
    "debug": false
  },
  "detection": {
    "enable_ml": true,
    "threshold": 0.7
  }
}
EOF
        print_success "Configuration file created"
    fi
}

# Verify installation
verify_installation() {
    print_header "Verifying Installation"
    
    # Check Python packages
    python3 -c "import ryu; print('✓ Ryu installed')" 2>/dev/null && print_success "Ryu" || print_error "Ryu"
    python3 -c "import flask; print('✓ Flask installed')" 2>/dev/null && print_success "Flask" || print_error "Flask"
    python3 -c "import mininet; print('✓ Mininet installed')" 2>/dev/null && print_success "Mininet" || print_error "Mininet"
    python3 -c "import scapy; print('✓ Scapy installed')" 2>/dev/null && print_success "Scapy" || print_error "Scapy"
    
    # Check system tools
    command -v ovs-vsctl &> /dev/null && print_success "OpenVSwitch" || print_error "OpenVSwitch"
    command -v suricata &> /dev/null && print_success "Suricata" || print_error "Suricata"
}

# Final instructions
print_instructions() {
    print_header "Setup Complete!"
    
    cat << 'EOF'

Next steps to run the system:

1. Start the Ryu Controller:
   ryu-manager src/controller/sdn_controller.py

2. In another terminal, start the Dashboard:
   python3 src/dashboard/app.py

3. In another terminal, create network topology:
   sudo python3 src/network/topology.py simple

4. Run the demo attack simulation:
   bash scripts/run_demo.sh

For more information, see docs/DEPLOYMENT.md

EOF
}

# Main execution
main() {
    print_header "SDN-NIDPS Project Setup"
    
    check_os
    check_root
    
    create_directories
    install_dependencies
    install_python_deps
    create_files
    init_database
    configure_suricata
    verify_installation
    print_instructions
    
    print_success "Setup completed successfully!"
}

# Run main
main "$@"
