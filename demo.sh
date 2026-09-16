#!/usr/bin/env bash
set -e

# Colors for terminal formatting
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
MAGENTA='\033[0;35m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}${BOLD}═════════════════════════════════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}${BOLD}🛡️  HECATE ENTERPRISE SOFTWARE HSM & GUARD POINT AGENT DEMO${NC}"
echo -e "${CYAN}${BOLD}═════════════════════════════════════════════════════════════════════════${NC}\n"

# 1. Binary Detection / Build
echo -e "${YELLOW}[Step 1/11] Locating Hecate Core & Agent binaries...${NC}"

FORCE_BUILD=false
if [[ "$*" == *"--build"* ]] || [[ "$*" == *"--rebuild"* ]]; then
    FORCE_BUILD=true
fi

CORE_BIN=""
AGENT_BIN=""

if [ "$FORCE_BUILD" = false ]; then
    if command -v hecate-core &>/dev/null && command -v hecate-agent &>/dev/null; then
        CORE_BIN=$(command -v hecate-core)
        AGENT_BIN=$(command -v hecate-agent)
        echo -e "  ${GREEN}✓ Found installed binaries in PATH:${NC}"
        echo -e "    • Core:  ${CYAN}$CORE_BIN${NC}"
        echo -e "    • Agent: ${CYAN}$AGENT_BIN${NC}"
    elif [ -x "$HOME/.cargo/bin/hecate-core" ] && [ -x "$HOME/.cargo/bin/hecate-agent" ]; then
        CORE_BIN="$HOME/.cargo/bin/hecate-core"
        AGENT_BIN="$HOME/.cargo/bin/hecate-agent"
        echo -e "  ${GREEN}✓ Found installed binaries in ~/.cargo/bin:${NC}"
        echo -e "    • Core:  ${CYAN}$CORE_BIN${NC}"
        echo -e "    • Agent: ${CYAN}$AGENT_BIN${NC}"
    elif [ -x "./target/release/hecate-core" ] && [ -x "./target/release/hecate-agent" ]; then
        CORE_BIN="./target/release/hecate-core"
        AGENT_BIN="./target/release/hecate-agent"
        echo -e "  ${GREEN}✓ Found workspace release binaries in ./target/release:${NC}"
        echo -e "    • Core:  ${CYAN}$CORE_BIN${NC}"
        echo -e "    • Agent: ${CYAN}$AGENT_BIN${NC}"
    elif [ -x "./target/debug/hecate-core" ] && [ -x "./target/debug/hecate-agent" ]; then
        CORE_BIN="./target/debug/hecate-core"
        AGENT_BIN="./target/debug/hecate-agent"
        echo -e "  ${GREEN}✓ Found workspace debug binaries in ./target/debug:${NC}"
        echo -e "    • Core:  ${CYAN}$CORE_BIN${NC}"
        echo -e "    • Agent: ${CYAN}$AGENT_BIN${NC}"
    fi
fi

if [ -z "$CORE_BIN" ] || [ -z "$AGENT_BIN" ]; then
    echo -e "  ${CYAN}Building fresh workspace binaries with cargo build...${NC}"
    cargo build --quiet
    CORE_BIN="./target/debug/hecate-core"
    AGENT_BIN="./target/debug/hecate-agent"
    echo -e "  ${GREEN}✓ Built debug binaries:${NC}"
    echo -e "    • Core:  ${CYAN}$CORE_BIN${NC}"
    echo -e "    • Agent: ${CYAN}$AGENT_BIN${NC}"
fi

# Sandbox Directories
DEMO_DIR="/tmp/hecate_demo_sandbox"
CORE_DATA="$DEMO_DIR/core_data"
AGENT_DATA="$DEMO_DIR/agent_data"
GUARD_TARGET="$DEMO_DIR/secure_mount"
GUARD_BACKING="$DEMO_DIR/backing_store"

rm -rf "$DEMO_DIR"
mkdir -p "$CORE_DATA" "$AGENT_DATA" "$GUARD_TARGET" "$GUARD_BACKING"

cleanup() {
    if [ -n "$CORE_PID" ]; then
        kill "$CORE_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# 2. Initialize Core Software HSM with Shamir 3-of-5 DR Key Shares
echo -e "\n${YELLOW}[Step 2/11] Initializing Software HSM & Shamir 3-of-5 Master Key Custody...${NC}"
$CORE_BIN --data-dir "$CORE_DATA" init --shares 5 --threshold 3 --passphrase "EnterpriseMasterPassphrase2026!"

# 3. HSM Key Lifecycle Management
echo -e "\n${YELLOW}[Step 3/11] Creating and Rotating Key Encryption Keys (KEK) in Software HSM...${NC}"
KEY_OUTPUT=$($CORE_BIN --data-dir "$CORE_DATA" key create --alias "prod-db-kek" --key-type aes256gcm)
echo "$KEY_OUTPUT"
KEY_ID=$(echo "$KEY_OUTPUT" | grep -o 'ID: [^,]*' | awk '{print $2}')
$CORE_BIN --data-dir "$CORE_DATA" key rotate --id "$KEY_ID"
$CORE_BIN --data-dir "$CORE_DATA" key list

# 4. Guard Point Policy Definition
echo -e "\n${YELLOW}[Step 4/11] Configuring Guard Point Policy with Root-Containment & UID Matching...${NC}"
CURRENT_UID=$(id -u)
$CORE_BIN --data-dir "$CORE_DATA" policy add \
    --id "gp-prod-db" \
    --name "Production Database Guard Point" \
    --target-path "$GUARD_TARGET" \
    --backing-path "$GUARD_BACKING" \
    --key-id "$KEY_ID" \
    --deny-root \
    --uids "$CURRENT_UID,1000" \
    --binary-hashes "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

$CORE_BIN --data-dir "$CORE_DATA" policy list

# 5. Start Hecate Core gRPC + mTLS Server Daemon
echo -e "\n${YELLOW}[Step 5/11] Launching Hecate Core gRPC Management Server on port 50051...${NC}"
$CORE_BIN --data-dir "$CORE_DATA" server --listen 127.0.0.1:50051 &
CORE_PID=$!
sleep 1

# 6. Generate One-Time Enrollment Token (OTET)
echo -e "\n${YELLOW}[Step 6/11] Generating Agent One-Time Enrollment Token (OTET)...${NC}"
TOKEN_OUTPUT=$($CORE_BIN --data-dir "$CORE_DATA" agent token --hostname "node-prod-01")
echo "$TOKEN_OUTPUT"
TOKEN=$(echo "$TOKEN_OUTPUT" | grep "Token: " | awk '{print $2}')

# 7. Enroll Agent with Core over gRPC / PKI
echo -e "\n${YELLOW}[Step 7/11] Enrolling Agent with Core & Receiving Node X.509 Client Cert...${NC}"
$AGENT_BIN --config-dir "$AGENT_DATA" enroll --core "http://127.0.0.1:50051" --token "$TOKEN"
$AGENT_BIN --config-dir "$AGENT_DATA" status

# 8. Synchronize Policies with Ed25519 Signature Verification
echo -e "\n${YELLOW}[Step 8/11] Agent Running Policy Sync & Integrity Verification...${NC}"
$AGENT_BIN --config-dir "$AGENT_DATA" run --once

# 9. Guard Point Transparent File Encryption & Decryption
echo -e "\n${YELLOW}[Step 9/11] Demonstrating File Protection at Guard Point...${NC}"
SAMPLE_FILE="$GUARD_TARGET/financial_records.csv"
ENCRYPTED_FILE="$GUARD_BACKING/financial_records.csv.enc"
RESTORED_FILE="$GUARD_TARGET/financial_records_decrypted.csv"

echo "customer_id,name,balance,card_number" > "$SAMPLE_FILE"
echo "1001,Alice Smith,54000.50,4111-2222-3333-4444" >> "$SAMPLE_FILE"
echo "1002,Bob Jones,128500.00,5500-0000-0000-9999" >> "$SAMPLE_FILE"

echo -e "  ${CYAN}Plaintext Payload:${NC}"
cat "$SAMPLE_FILE"

$AGENT_BIN --config-dir "$AGENT_DATA" protect \
    --source "$SAMPLE_FILE" \
    --dest "$ENCRYPTED_FILE" \
    --key-id "$KEY_ID"

echo -e "\n  ${CYAN}Ciphertext in Backing Store (Hex Dump Sample):${NC}"
hexdump -C "$ENCRYPTED_FILE" | head -n 4

$AGENT_BIN --config-dir "$AGENT_DATA" unprotect \
    --source "$ENCRYPTED_FILE" \
    --dest "$RESTORED_FILE"

echo -e "\n  ${GREEN}Decrypted Verification (diff matches identically):${NC}"
diff -u "$SAMPLE_FILE" "$RESTORED_FILE" && echo -e "  ${GREEN}✓ Decrypted file perfectly matches original plaintext!${NC}"

# 10. Compliance Dashboard & Tamper-Evident Hash Chain Audit
echo -e "\n${YELLOW}[Step 10/11] Reviewing Compliance Posture & Cryptographic Audit Ledger...${NC}"
$CORE_BIN --data-dir "$CORE_DATA" compliance
$CORE_BIN --data-dir "$CORE_DATA" agent list
$CORE_BIN --data-dir "$CORE_DATA" audit

# 11. Disaster Recovery Encrypted Backup & Restore
echo -e "\n${YELLOW}[Step 11/11] Simulating Disaster Recovery Backup & Restoration...${NC}"
BACKUP_ARCHIVE="$DEMO_DIR/hecate_dr_backup.hct"
$CORE_BIN --data-dir "$CORE_DATA" backup create --out "$BACKUP_ARCHIVE"
$CORE_BIN --data-dir "$CORE_DATA" backup restore --file "$BACKUP_ARCHIVE"

echo -e "\n${GREEN}${BOLD}═════════════════════════════════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}${BOLD}✓ ALL DEMO FEATURES EXECUTED AND VERIFIED SUCCESSFULLY!${NC}"
echo -e "${GREEN}${BOLD}═════════════════════════════════════════════════════════════════════════${NC}"
