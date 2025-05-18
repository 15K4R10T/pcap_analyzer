#!/bin/bash

# Colors and formatting
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# File to analyze
PCAP_FILE="log_analysis_5.pcapng"

# Function for section headers
print_header() {
    local header="$1"
    local line_length=70
    echo ""
    echo -e "${BLUE}${BOLD}┌$( printf '─%.0s' $(seq 1 $line_length) )┐${NC}"
    echo -e "${BLUE}${BOLD}│${NC} ${GREEN}${BOLD}$header${NC} $( printf ' %.0s' $(seq 1 $(( $line_length - ${#header} - 2 )) ) )${BLUE}${BOLD}│${NC}"
    echo -e "${BLUE}${BOLD}└$( printf '─%.0s' $(seq 1 $line_length) )┘${NC}"
    echo ""
}

# Function for subsection headers
print_subheader() {
    local subheader="$1"
    echo -e "${YELLOW}${BOLD}» $subheader${NC}"
    echo -e "${YELLOW}$( printf '─%.0s' $(seq 1 50) )${NC}"
}

# Function to check command existence
check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}${BOLD}ERROR:${NC} $1 tidak ditemukan. Silakan install dengan:"
        echo -e "  ${BOLD}sudo apt-get install $2${NC}"
        exit 1
    fi
}

# Print banner
echo -e "${BLUE}${BOLD}"
echo "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓"
echo "┃                  PCAP/PCAPNG NETWORK ANALYZER                    ┃"
echo "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛"
echo -e "${NC}"
echo -e "File: ${BOLD}$PCAP_FILE${NC}"
echo -e "Date: ${BOLD}$(date)${NC}"
echo ""

# Check dependencies
check_command "tshark" "tshark"

# Create output directories
mkdir -p pcap_files 2>/dev/null
mkdir -p pcap_ftp_files 2>/dev/null

# Main analysis functions
analyze_protocols() {
    print_header "PROTOKOL SERVICE YANG DITEMUKAN"
    tshark -r "$PCAP_FILE" -T fields -e frame.protocols | sort | uniq -c | sort -nr | 
        awk '{printf "%-4s %s\n", $1, $2}'
}

analyze_ports() {
    print_header "PORT TCP/UDP YANG DIGUNAKAN"
    print_subheader "Top 20 Ports"
    tshark -r "$PCAP_FILE" -Y "tcp || udp" -T fields -e tcp.port -e udp.port | 
        grep -v '^$' | sort | uniq -c | sort -nr | head -20 | 
        awk '{printf "%-4s Port: %s\n", $1, $2}'
}

analyze_file_transfers() {
    print_header "FILE TRANSFERS"
    
    print_subheader "FTP Transfers"
    ftp_transfers=$(tshark -r "$PCAP_FILE" -Y "ftp.request.command == \"RETR\" || ftp.request.command == \"STOR\"" \
        -T fields -e ftp.request.command -e ftp.request.arg | grep -v '^$')
    
    if [ -z "$ftp_transfers" ]; then
        echo "No FTP transfers detected"
    else
        echo "$ftp_transfers" | awk '{printf "%-5s %s\n", $1, $2}'
    fi
    
    print_subheader "HTTP Transfers"
    http_transfers=$(tshark -r "$PCAP_FILE" -Y "http.request.method == \"GET\" || http.request.method == \"POST\"" \
        -T fields -e http.request.method -e http.request.uri | grep -i -E "\.([a-z0-9]{2,4})$" | sort | uniq -c | sort -nr | head -20)
    
    if [ -z "$http_transfers" ]; then
        echo "No HTTP file transfers detected"
    else
        echo "$http_transfers" | awk '{printf "%-4s %-4s %s\n", $1, $2, $3}'
    fi
    
    print_subheader "SMB Transfers"
    smb_transfers=$(tshark -r "$PCAP_FILE" -Y "smb || smb2" -T fields -e smb2.filename -e smb.path | grep -v '^$' | sort | uniq -c | sort -nr | head -20)
    
    if [ -z "$smb_transfers" ]; then
        echo "No SMB transfers detected"
    else
        echo "$smb_transfers" | awk '{printf "%-4s %s\n", $1, $2}'
    fi
}

analyze_dns() {
    print_header "DNS QUERIES"
    dns_queries=$(tshark -r "$PCAP_FILE" -Y "dns" -T fields -e dns.qry.name | sort | uniq -c | sort -nr | head -20)
    
    if [ -z "$dns_queries" ]; then
        echo "No DNS queries detected"
    else
        echo "$dns_queries" | awk '{printf "%-4s %s\n", $1, $2}'
    fi
}

analyze_user_agents() {
    print_header "HTTP USER AGENTS"
    ua_data=$(tshark -r "$PCAP_FILE" -Y "http.user_agent" -T fields -e http.user_agent | sort | uniq -c | sort -nr | head -10)
    
    if [ -z "$ua_data" ]; then
        echo "No user agents detected"
    else
        echo "$ua_data" | awk '{printf "%-4s %s\n", $1, substr($0, length($1)+2)}'
    fi
}

analyze_email() {
    print_header "EMAIL PROTOCOLS (SMTP/POP/IMAP)"
    email_data=$(tshark -r "$PCAP_FILE" -Y "smtp || pop || imap" -T fields -e smtp.req.command -e smtp.req.parameter -e pop.request.command -e imap.req.command | grep -v '^$' | head -20)
    
    if [ -z "$email_data" ]; then
        echo "No email protocol traffic detected"
    else
        echo "$email_data"
    fi
}

analyze_ssh() {
    print_header "SSH CONNECTIONS"
    ssh_data=$(tshark -r "$PCAP_FILE" -Y "ssh" -T fields -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport | sort | uniq -c | sort -nr)
    
    if [ -z "$ssh_data" ]; then
        echo "No SSH connections detected"
    else
        echo "$ssh_data" | awk '{printf "%-4s Source: %-15s:%-5s → Destination: %-15s:%-5s\n", $1, $2, $4, $3, $5}'
    fi
}

analyze_file_references() {
    print_header "POTENTIAL FILE REFERENCES IN PACKETS"
    file_refs=$(tshark -r "$PCAP_FILE" -Y "data-text-lines" -T fields -e data-text-lines | grep -i -E "file|\.([a-z0-9]{2,4})$" | sort | uniq | head -30)
    
    if [ -z "$file_refs" ]; then
        echo "No file references detected"
    else
        echo "$file_refs"
    fi
}

analyze_service_file_combinations() {
    print_header "POTENTIAL SERVICE:FILE COMBINATIONS"
    
    print_subheader "FTP Files"
    ftp_files=$(tshark -r "$PCAP_FILE" -Y "ftp.request.command == \"RETR\" || ftp.request.command == \"STOR\"" -T fields -e ftp.request.arg | grep -v '^$' | sort | uniq)
    
    if [ -z "$ftp_files" ]; then
        echo "No FTP files detected"
    else
        while read -r file; do
            echo "ftp:$file"
        done <<< "$ftp_files"
    fi
    
    print_subheader "HTTP Files"
    http_files=$(tshark -r "$PCAP_FILE" -Y "http.request.method == \"GET\" || http.request.method == \"POST\"" -T fields -e http.request.uri | grep -i -E "\.([a-z0-9]{2,4})$" | sort | uniq)
    
    if [ -z "$http_files" ]; then
        echo "No HTTP files detected"
    else
        while read -r file; do
            echo "http:$file"
        done <<< "$http_files"
    fi
    
    print_subheader "SMB Files"
    smb_files=$(tshark -r "$PCAP_FILE" -Y "smb || smb2" -T fields -e smb2.filename -e smb.path | grep -v '^$' | sort | uniq)
    
    if [ -z "$smb_files" ]; then
        echo "No SMB files detected"
    else
        while read -r file; do
            echo "smb:$file"
        done <<< "$smb_files"
    fi
}

# extract_objects() {
#     print_header "EXTRACTING OBJECTS"
    
#     print_subheader "Extracting HTTP Objects"
#     tshark -r "$PCAP_FILE" --export-objects "http,pcap_files" 2>/dev/null
#     http_count=$(find pcap_files -type f | wc -l)
#     echo -e "${BOLD}$http_count${NC} HTTP objects extracted to ${BOLD}pcap_files/${NC} directory"
    
#     print_subheader "Extracting FTP-DATA Objects"
#     tshark -r "$PCAP_FILE" --export-objects "ftp-data,pcap_ftp_files" 2>/dev/null
#     ftp_count=$(find pcap_ftp_files -type f | wc -l)
#     echo -e "${BOLD}$ftp_count${NC} FTP-DATA objects extracted to ${BOLD}pcap_ftp_files/${NC} directory"
# }

find_service_file_strings() {
    print_header "SEARCHING FOR SERVICE:FILE STRINGS"
    service_file_strings=$(tshark -r "$PCAP_FILE" -Y "data-text-lines" -T fields -e data-text-lines | grep -i -E "[a-z]+:[a-z0-9._-]+" | sort | uniq | head -50)
    
    if [ -z "$service_file_strings" ]; then
        echo "No service:file strings detected"
    else
        echo "$service_file_strings"
    fi
}

# Execute analysis functions
analyze_protocols
analyze_ports
analyze_file_transfers
analyze_dns
analyze_user_agents
analyze_email
analyze_ssh
analyze_file_references
analyze_service_file_combinations
extract_objects
find_service_file_strings

# Summary report
print_header "ANALISIS SUMMARY"
echo -e "Analisis selesai pada: ${BOLD}$(date)${NC}"
echo -e "File yang dianalisis: ${BOLD}$PCAP_FILE${NC}"
echo -e "HTTP Objects: ${BOLD}$(find pcap_files -type f | wc -l)${NC} files"
echo -e "FTP-DATA Objects: ${BOLD}$(find pcap_ftp_files -type f | wc -l)${NC} files"
echo ""
echo -e "${GREEN}${BOLD}Analisis selesai! Periksa hasil di atas untuk kombinasi service:file yang relevan.${NC}"

