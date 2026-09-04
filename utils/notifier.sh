#!/bin/bash

# ReconX Multi-Platform Webhook Notification Utility
# Delivers formatted alerts to Discord, Telegram, and Slack.

notifier_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="${BASE_DIR:-$(cd "$notifier_dir/.." && pwd)}"

source "$BASE_DIR/utils/colors.sh"
source "$BASE_DIR/utils/logger.sh"

[[ -f "$BASE_DIR/config/tools.conf" ]] && source "$BASE_DIR/config/tools.conf"

send_webhook_alert() {
    local domain="$1"
    local report_file="$2"
    
    local summary="🔍 **ReconX Alert**: Changes detected for **$domain**"
    if [[ -f "$report_file" ]]; then
        summary="$(head -n 25 "$report_file")"
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # 1. Discord Webhook
    # ═══════════════════════════════════════════════════════════════
    if [[ -n "$DISCORD_WEBHOOK_URL" ]]; then
        log_info "Dispatching notification to Discord webhook..."
        
        # Escape JSON payload safely
        local json_payload=$(python3 -c '
import json, sys
domain = sys.argv[1]
text = sys.argv[2]
payload = {
    "username": "ReconX Bot",
    "avatar_url": "https://raw.githubusercontent.com/projectdiscovery/nuclei/main/static/nuclei-logo.png",
    "embeds": [{
        "title": f"🚨 ReconX Asset Alert: {domain}",
        "description": text[:2000],
        "color": 15158332,
        "footer": {"text": "ReconX Continuous Recon Engine"}
    }]
}
print(json.dumps(payload))
' "$domain" "$summary" 2>/dev/null)
        
        curl -s -H "Content-Type: application/json" -X POST -d "$json_payload" "$DISCORD_WEBHOOK_URL" >/dev/null 2>&1 &
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # 2. Telegram Bot
    # ═══════════════════════════════════════════════════════════════
    if [[ -n "$TELEGRAM_BOT_TOKEN" ]] && [[ -n "$TELEGRAM_CHAT_ID" ]]; then
        log_info "Dispatching notification to Telegram channel..."
        local tg_msg="🚨 *ReconX Asset Alert*: $domain%0A%0A$summary"
        curl -s "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
            -d "chat_id=${TELEGRAM_CHAT_ID}" \
            -d "text=${summary}" \
            -d "parse_mode=Markdown" >/dev/null 2>&1 &
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # 3. Slack Webhook
    # ═══════════════════════════════════════════════════════════════
    if [[ -n "$SLACK_WEBHOOK_URL" ]]; then
        log_info "Dispatching notification to Slack webhook..."
        local slack_payload=$(python3 -c '
import json, sys
text = sys.argv[1]
print(json.dumps({"text": text}))
' "$summary" 2>/dev/null)
        
        curl -s -H "Content-Type: application/json" -X POST -d "$slack_payload" "$SLACK_WEBHOOK_URL" >/dev/null 2>&1 &
    fi
}
