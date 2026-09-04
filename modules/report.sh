#!/bin/bash

# Enhanced Report Generation Module
# Supports multiple export formats: MD, HTML, JSON, CSV, PDF

generate_report() {
    local target=$1
    local OUT="output/$target"
    local REPORT_DIR="$OUT/reports"
    mkdir -p "$REPORT_DIR"
    
    log_section "REPORT GENERATION - $target"
    
    local report_date=$(date '+%Y-%m-%d %H:%M:%S')
    local report_timestamp=$(date '+%Y%m%d_%H%M%S')
    
    # Collect all data
    local subdomains_count=0
    local ports_count=0
    local vuln_critical=0
    local vuln_high=0
    local vuln_medium=0
    local vuln_low=0
    local vuln_total=0
    
    [[ -f "$OUT/passive/subdomains.txt" ]] && subdomains_count=$(wc -l < "$OUT/passive/subdomains.txt" 2>/dev/null || echo 0)
    [[ -f "$OUT/active/open_ports_list.txt" ]] && ports_count=$(wc -l < "$OUT/active/open_ports_list.txt" 2>/dev/null || echo 0)
    
    # Count vulnerabilities
    for json_file in "$OUT/vuln"/*.json; do
        [[ -f "$json_file" ]] || continue
        vuln_critical=$((vuln_critical + $(grep -c '"severity":"critical"' "$json_file" 2>/dev/null || true)))
        vuln_high=$((vuln_high + $(grep -c '"severity":"high"' "$json_file" 2>/dev/null || true)))
        vuln_medium=$((vuln_medium + $(grep -c '"severity":"medium"' "$json_file" 2>/dev/null || true)))
        vuln_low=$((vuln_low + $(grep -c '"severity":"low"' "$json_file" 2>/dev/null || true)))
    done
    vuln_total=$((vuln_critical + vuln_high + vuln_medium + vuln_low))
    
    # Generate Markdown Report
    generate_markdown_report "$target" "$REPORT_DIR" "$report_date" "$subdomains_count" "$ports_count" "$vuln_critical" "$vuln_high" "$vuln_medium" "$vuln_low" "$vuln_total"
    
    log_success "Report generated: $REPORT_DIR/report_${report_timestamp}.md"
}

# Generate Markdown Report
generate_markdown_report() {
    local target=$1
    local REPORT_DIR=$2
    local report_date=$3
    local subdomains_count=$4
    local ports_count=$5
    local vuln_critical=$6
    local vuln_high=$7
    local vuln_medium=$8
    local vuln_low=$9
    local vuln_total=${10}
    
    local OUT="output/$target"
    local report_timestamp=$(date '+%Y%m%d_%H%M%S')
    local REPORT="$REPORT_DIR/report_${report_timestamp}.md"
    
    {
        echo "# 🔍 ReconX Security Assessment Report"
        echo ""
        echo "---"
        echo ""
        echo "## 📋 Executive Summary"
        echo ""
        echo "| Field | Value |"
        echo "|-------|-------|"
        echo "| **Target** | \`$target\` |"
        echo "| **Report Date** | $report_date |"
        echo "| **Robustness Level** | ${ROBUSTNESS_LEVEL:-3}/5 |"
        echo "| **Scan Mode** | ${MODE:-normal} |"
        echo ""
        echo "### Key Findings Overview"
        echo ""
        echo "| Metric | Count |"
        echo "|--------|-------|"
        echo "| Subdomains Discovered | $subdomains_count |"
        echo "| Open Ports | $ports_count |"
        echo "| Total Vulnerabilities | $vuln_total |"
        echo ""
        echo "### Vulnerability Severity Breakdown"
        echo ""
        echo "| Severity | Count | Risk Level |"
        echo "|----------|-------|------------|"
        echo "| 🔴 Critical | $vuln_critical | Immediate Action Required |"
        echo "| 🟠 High | $vuln_high | High Priority |"
        echo "| 🟡 Medium | $vuln_medium | Medium Priority |"
        echo "| 🟢 Low | $vuln_low | Low Priority |"
        echo ""
        echo "---"
        echo ""
        echo "## 🌐 Reconnaissance Results"
        echo ""
        echo "### Passive Reconnaissance"
        echo ""
        if [[ -f "$OUT/passive/subdomains.txt" ]]; then
            echo "#### Discovered Subdomains ($subdomains_count)"
            echo ""
            echo "\`\`\`"
            head -50 "$OUT/passive/subdomains.txt"
            [[ $subdomains_count -gt 50 ]] && echo "... and $((subdomains_count - 50)) more"
            echo "\`\`\`"
        else
            echo "*No subdomain data available*"
        fi
        echo ""
        
        if [[ -f "$OUT/passive/whois.txt" ]]; then
            echo "#### WHOIS Information"
            echo ""
            echo "\`\`\`"
            head -30 "$OUT/passive/whois.txt"
            echo "\`\`\`"
        fi
        echo ""
        
        echo "### DNS Reconnaissance"
        echo ""
        for dns_file in "$OUT/dns"/*.txt; do
            [[ -f "$dns_file" ]] || continue
            local dns_type=$(basename "$dns_file" .txt | tr '[:lower:]' '[:upper:]')
            echo "#### $dns_type Records"
            echo ""
            echo "\`\`\`"
            cat "$dns_file"
            echo "\`\`\`"
            echo ""
        done
        
        echo "---"
        echo ""
        echo "## 🔓 Open Ports & Services"
        echo ""
        if [[ -f "$OUT/active/open_ports_list.txt" ]]; then
            echo "### Open Ports ($ports_count)"
            echo ""
            echo "| Port | Protocol |"
            echo "|------|----------|"
            while IFS= read -r port; do
                echo "| $port | TCP |"
            done < "$OUT/active/open_ports_list.txt"
            echo ""
        fi
        
        if [[ -f "$OUT/active/services.txt" ]]; then
            echo "### Service Detection"
            echo ""
            echo "\`\`\`"
            grep -E "^[0-9]+/(tcp|udp)" "$OUT/active/services.txt" | head -30
            echo "\`\`\`"
        fi
        echo ""
        
        echo "---"
        echo ""
        echo "## 🌍 Web Reconnaissance"
        echo ""
        if [[ -f "$OUT/web/live.txt" ]]; then
            echo "### Live Web Hosts"
            echo ""
            echo "\`\`\`"
            cat "$OUT/web/live.txt"
            echo "\`\`\`"
        fi
        echo ""
        
        if [[ -f "$OUT/web/whatweb.txt" ]]; then
            echo "### Technology Stack"
            echo ""
            echo "\`\`\`"
            head -20 "$OUT/web/whatweb.txt"
            echo "\`\`\`"
        fi
        echo ""
        
        if [[ -f "$OUT/web/ffuf.json" ]]; then
            echo "### Directory Enumeration"
            echo ""
            echo "\`\`\`"
            if command -v jq >/dev/null 2>&1; then
                jq -r '.results[] | "\(.status) - \(.url)"' "$OUT/web/ffuf.json" 2>/dev/null | head -30
            elif command -v python3 >/dev/null 2>&1; then
                python3 -c '
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    for r in d.get("results", [])[:30]:
        print(f"{r.get(\"status\")} - {r.get(\"url\")}")
except Exception: pass
' "$OUT/web/ffuf.json" 2>/dev/null
            fi
            echo "\`\`\`"
        fi
        echo ""
        
        echo "---"
        echo ""
        echo "## ⚠️ Vulnerability Assessment"
        echo ""
        echo "### Critical Vulnerabilities ($vuln_critical)"
        echo ""
        if [[ $vuln_critical -gt 0 ]]; then
            echo "| Vulnerability | Host | Description |"
            echo "|---------------|------|-------------|"
            for json_file in "$OUT/vuln"/*.json; do
                [[ -f "$json_file" ]] || continue
                [[ "$json_file" == *"consolidated.json"* ]] && continue
                if command -v jq >/dev/null 2>&1; then
                    jq -r 'select(.info.severity == "critical") | "| \(.info.name) | \(.host) | \(.info.description // "N/A" | .[0:50]) |"' "$json_file" 2>/dev/null
                elif command -v python3 >/dev/null 2>&1; then
                    python3 -c '
import json, sys
for line in open(sys.argv[1]):
    try:
        d = json.loads(line)
        if d.get("info", {}).get("severity") == "critical":
            desc = (d.get("info", {}).get("description") or "N/A")[:50]
            print(f"| {d.get(\"info\", {}).get(\"name\")} | {d.get(\"host\")} | {desc} |")
    except Exception: pass
' "$json_file" 2>/dev/null
                fi
            done
        else
            echo "*No critical vulnerabilities found*"
        fi
        echo ""
        
        echo "### High Severity Vulnerabilities ($vuln_high)"
        echo ""
        if [[ $vuln_high -gt 0 ]]; then
            echo "| Vulnerability | Host | Description |"
            echo "|---------------|------|-------------|"
            for json_file in "$OUT/vuln"/*.json; do
                [[ -f "$json_file" ]] || continue
                [[ "$json_file" == *"consolidated.json"* ]] && continue
                if command -v jq >/dev/null 2>&1; then
                    jq -r 'select(.info.severity == "high") | "| \(.info.name) | \(.host) | \(.info.description // "N/A" | .[0:50]) |"' "$json_file" 2>/dev/null
                elif command -v python3 >/dev/null 2>&1; then
                    python3 -c '
import json, sys
for line in open(sys.argv[1]):
    try:
        d = json.loads(line)
        if d.get("info", {}).get("severity") == "high":
            desc = (d.get("info", {}).get("description") or "N/A")[:50]
            print(f"| {d.get(\"info\", {}).get(\"name\")} | {d.get(\"host\")} | {desc} |")
    except Exception: pass
' "$json_file" 2>/dev/null
                fi
            done
        else
            echo "*No high severity vulnerabilities found*"
        fi
        echo ""
        
        echo "### Medium Severity Vulnerabilities ($vuln_medium)"
        echo ""
        if [[ $vuln_medium -gt 0 ]]; then
            echo "| Vulnerability | Host |"
            echo "|---------------|------|"
            for json_file in "$OUT/vuln"/*.json; do
                [[ -f "$json_file" ]] || continue
                [[ "$json_file" == *"consolidated.json"* ]] && continue
                if command -v jq >/dev/null 2>&1; then
                    jq -r 'select(.info.severity == "medium") | "| \(.info.name) | \(.host) |"' "$json_file" 2>/dev/null | head -20
                elif command -v python3 >/dev/null 2>&1; then
                    python3 -c '
import json, sys
for line in open(sys.argv[1]):
    try:
        d = json.loads(line)
        if d.get("info", {}).get("severity") == "medium":
            print(f"| {d.get(\"info\", {}).get(\"name\")} | {d.get(\"host\")} |")
    except Exception: pass
' "$json_file" 2>/dev/null | head -20
                fi
            done
        else
            echo "*No medium severity vulnerabilities found*"
        fi
        echo ""
        
        echo "---"
        echo ""
        echo "## 📊 Recommendations"
        echo ""
        echo "### Immediate Actions (Critical)"
        echo ""
        if [[ $vuln_critical -gt 0 ]]; then
            echo "1. Address all critical vulnerabilities immediately"
            echo "2. Implement emergency patches for affected systems"
            echo "3. Consider taking vulnerable services offline until patched"
        else
            echo "- No critical issues requiring immediate action"
        fi
        echo ""
        
        echo "### Short-term Actions (High Priority)"
        echo ""
        if [[ $vuln_high -gt 0 ]]; then
            echo "1. Schedule patches for high severity vulnerabilities within 7 days"
            echo "2. Review and harden exposed services"
            echo "3. Implement additional monitoring for affected systems"
        else
            echo "- No high priority issues identified"
        fi
        echo ""
        
        echo "### Medium-term Actions"
        echo ""
        echo "1. Review and update security configurations"
        echo "2. Implement regular vulnerability scanning"
        echo "3. Review access controls and authentication mechanisms"
        echo "4. Update security policies and procedures"
        echo ""
        
        echo "---"
        echo ""
        echo "## 📁 Appendix"
        echo ""
        echo "### Scan Configuration"
        echo ""
        echo "| Parameter | Value |"
        echo "|-----------|-------|"
        echo "| Robustness Level | ${ROBUSTNESS_LEVEL:-3} |"
        echo "| Scan Mode | ${MODE:-normal} |"
        echo "| Report Generated | $report_date |"
        echo ""
        
        echo "### Files Generated"
        echo ""
        echo "\`\`\`"
        find "$OUT" -type f -name "*.txt" -o -name "*.json" -o -name "*.xml" 2>/dev/null | head -50
        echo "\`\`\`"
        echo ""
        
        echo "---"
        echo ""
        echo "*Report generated by ReconX v2.0*"
        echo ""
        echo "*This report is confidential and intended for authorized personnel only.*"
        
    } > "$REPORT"
    
    # Also create a symlink to latest report
    ln -sf "report_${report_timestamp}.md" "$REPORT_DIR/report_latest.md"
}

# Export report to different formats
export_report() {
    local target=$1
    local formats=$2
    local OUT="output/$target"
    local REPORT_DIR="$OUT/reports"
    mkdir -p "$REPORT_DIR"
    
    local report_timestamp=$(date '+%Y%m%d_%H%M%S')
    
    # Split comma-separated formats if provided
    IFS=',' read -ra fmt_array <<< "$formats"
    
    for format in "${fmt_array[@]}"; do
        format=$(echo "$format" | tr -d '[:space:]')
        [[ -z "$format" ]] && continue
        log_info "Exporting report in $format format..."
        
        case "$format" in
            "md"|"markdown")
                generate_report "$target"
                ;;
            "html")
                export_html_report "$target" "$REPORT_DIR" "$report_timestamp"
                ;;
            "json")
                export_json_report "$target" "$REPORT_DIR" "$report_timestamp"
                ;;
            "csv")
                export_csv_report "$target" "$REPORT_DIR" "$report_timestamp"
                ;;
            "pdf")
                export_pdf_report "$target" "$REPORT_DIR" "$report_timestamp"
                ;;
            "all")
                generate_report "$target"
                export_html_report "$target" "$REPORT_DIR" "$report_timestamp"
                export_json_report "$target" "$REPORT_DIR" "$report_timestamp"
                export_csv_report "$target" "$REPORT_DIR" "$report_timestamp"
                export_pdf_report "$target" "$REPORT_DIR" "$report_timestamp"
                ;;
            *)
                log_error "Unknown format: $format"
                ;;
        esac
    done
}

# Export HTML Report
export_html_report() {
    local target=$1
    local REPORT_DIR=$2
    local report_timestamp=$3
    local OUT="output/$target"
    local REPORT="$REPORT_DIR/report_${report_timestamp}.html"
    
    log_tool "html-export" "start"
    
    # Collect data
    local subdomains_count=0
    local ports_count=0
    local vuln_critical=0 vuln_high=0 vuln_medium=0 vuln_low=0
    
    [[ -f "$OUT/passive/subdomains.txt" ]] && subdomains_count=$(wc -l < "$OUT/passive/subdomains.txt" 2>/dev/null || echo 0)
    [[ -f "$OUT/active/open_ports_list.txt" ]] && ports_count=$(wc -l < "$OUT/active/open_ports_list.txt" 2>/dev/null || echo 0)
    
    for json_file in "$OUT/vuln"/*.json; do
        [[ -f "$json_file" ]] || continue
        vuln_critical=$((vuln_critical + $(grep -c '"severity":"critical"' "$json_file" 2>/dev/null || true)))
        vuln_high=$((vuln_high + $(grep -c '"severity":"high"' "$json_file" 2>/dev/null || true)))
        vuln_medium=$((vuln_medium + $(grep -c '"severity":"medium"' "$json_file" 2>/dev/null || true)))
        vuln_low=$((vuln_low + $(grep -c '"severity":"low"' "$json_file" 2>/dev/null || true)))
    done
    
    cat > "$REPORT" << 'HTMLHEAD'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReconX Assessment Report</title>
    <style>
        :root {
            --bg: #0f172a;
            --card-bg: #1e293b;
            --card-border: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent: #38bdf8;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #22c55e;
            --info: #06b6d4;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--bg);
            color: var(--text-main);
            line-height: 1.6;
            padding: 2rem 1rem;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header {
            background: linear-gradient(135deg, #1e293b, #0f172a);
            border: 1px solid var(--card-border);
            padding: 2.5rem 2rem;
            border-radius: 1rem;
            margin-bottom: 2rem;
            box-shadow: 0 4px 20px rgba(0,0,0,0.4);
        }
        .header h1 { font-size: 2.2rem; color: var(--accent); margin-bottom: 0.5rem; display: flex; align-items: center; gap: 0.5rem; }
        .header p { color: var(--text-muted); font-size: 0.95rem; }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        .stat-card {
            background: var(--card-bg);
            padding: 1.25rem;
            border-radius: 0.75rem;
            border: 1px solid var(--card-border);
            text-align: center;
            transition: transform 0.2s ease;
        }
        .stat-card:hover { transform: translateY(-2px); }
        .stat-card .number { font-size: 2rem; font-weight: 700; }
        .stat-card .label { color: var(--text-muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 0.25rem; }
        .stat-card.critical { border-top: 4px solid var(--critical); }
        .stat-card.critical .number { color: var(--critical); }
        .stat-card.high { border-top: 4px solid var(--high); }
        .stat-card.high .number { color: var(--high); }
        .stat-card.medium { border-top: 4px solid var(--medium); }
        .stat-card.medium .number { color: var(--medium); }
        .stat-card.low { border-top: 4px solid var(--low); }
        .stat-card.low .number { color: var(--low); }
        .card {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 0.75rem;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }
        .card h2 {
            color: var(--accent);
            font-size: 1.25rem;
            margin-bottom: 1rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .search-box {
            padding: 0.5rem 1rem;
            border-radius: 0.5rem;
            border: 1px solid var(--card-border);
            background: #0f172a;
            color: var(--text-main);
            font-size: 0.875rem;
            width: 250px;
        }
        table { width: 100%; border-collapse: collapse; margin-top: 0.5rem; }
        th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--card-border); font-size: 0.9rem; }
        th { background: #162032; color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 0.75rem; }
        tr:hover { background: rgba(56, 189, 248, 0.04); }
        .badge {
            display: inline-block;
            padding: 0.2rem 0.6rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
        }
        .badge.critical { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }
        .badge.high { background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid #f97316; }
        .badge.medium { background: rgba(234, 179, 8, 0.2); color: #facc15; border: 1px solid #eab308; }
        .badge.low { background: rgba(34, 197, 94, 0.2); color: #4ade80; border: 1px solid #22c55e; }
        pre {
            background: #0b1120;
            border: 1px solid var(--card-border);
            color: #38bdf8;
            padding: 1rem;
            border-radius: 0.5rem;
            overflow-x: auto;
            font-family: 'Courier New', Courier, monospace;
            font-size: 0.85rem;
            max-height: 350px;
        }
        .footer { text-align: center; color: var(--text-muted); font-size: 0.85rem; margin-top: 2rem; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 ReconX Security Assessment</h1>
HTMLHEAD

    echo "            <p>Target: <strong style=\"color:#38bdf8;\">$target</strong> | Date: $(date '+%Y-%m-%d %H:%M:%S') | Robustness: ${ROBUSTNESS_LEVEL:-3}/5 | Mode: ${MODE:-normal}</p>" >> "$REPORT"
    echo "        </div>" >> "$REPORT"
    
    # Stats Grid
    cat >> "$REPORT" << HTMLSTATS
        <div class="stats-grid">
            <div class="stat-card">
                <div class="number">$subdomains_count</div>
                <div class="label">Subdomains</div>
            </div>
            <div class="stat-card">
                <div class="number">$ports_count</div>
                <div class="label">Open Ports</div>
            </div>
            <div class="stat-card critical">
                <div class="number">$vuln_critical</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="number">$vuln_high</div>
                <div class="label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="number">$vuln_medium</div>
                <div class="label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="number">$vuln_low</div>
                <div class="label">Low</div>
            </div>
        </div>
HTMLSTATS

    # Vulnerabilities Section with Search
    echo '        <div class="card">' >> "$REPORT"
    echo '            <h2><span>⚠️ Vulnerabilities & Findings</span> <input type="text" id="vulnSearch" class="search-box" placeholder="Filter vulnerabilities..." onkeyup="filterTable(\x27vulnTable\x27, this.value)"></h2>' >> "$REPORT"
    echo '            <table id="vulnTable">' >> "$REPORT"
    echo '                <thead><tr><th>Severity</th><th>Name</th><th>Host / Target</th><th>Protocol / Tag</th></tr></thead>' >> "$REPORT"
    echo '                <tbody>' >> "$REPORT"
    
    local found_any=false
    for json_file in "$OUT/vuln"/*.json; do
        [[ -f "$json_file" ]] || continue
        [[ "$json_file" == *"consolidated.json"* ]] && continue
        if command -v jq >/dev/null 2>&1; then
            while IFS= read -r row; do
                [[ -n "$row" ]] && echo "                    $row" >> "$REPORT" && found_any=true
            done < <(jq -r 'select(.info.severity != null) | "<tr><td><span class=\"badge \(.info.severity)\">\(.info.severity)</span></td><td>\(.info.name // "N/A")</td><td><code>\(.host // "N/A")</code></td><td>\(.type // "web")</td></tr>"' "$json_file" 2>/dev/null)
        elif command -v python3 >/dev/null 2>&1; then
            while IFS= read -r row; do
                [[ -n "$row" ]] && echo "                    $row" >> "$REPORT" && found_any=true
            done < <(python3 -c '
import json, sys
for line in open(sys.argv[1]):
    try:
        d = json.loads(line)
        info = d.get("info", {})
        sev = info.get("severity")
        if not sev: continue
        name = info.get("name", "N/A")
        host = d.get("host", "N/A")
        vtype = d.get("type", "web")
        print(f"<tr><td><span class=\"badge {sev}\">{sev}</span></td><td>{name}</td><td><code>{host}</code></td><td>{vtype}</td></tr>")
    except Exception: pass
' "$json_file" 2>/dev/null)
        fi
    done
    
    if ! $found_any; then
        echo '                    <tr><td colspan="4" style="text-align:center; color:#94a3b8;">No vulnerabilities recorded.</td></tr>' >> "$REPORT"
    fi
    
    echo '                </tbody>' >> "$REPORT"
    echo '            </table>' >> "$REPORT"
    echo '        </div>' >> "$REPORT"
    
    # Open Ports Section
    if [[ -f "$OUT/active/services.txt" ]]; then
        echo '        <div class="card">' >> "$REPORT"
        echo '            <h2>🔓 Open Ports & Services</h2>' >> "$REPORT"
        echo '            <pre>' >> "$REPORT"
        grep -E "^[0-9]+/(tcp|udp)" "$OUT/active/services.txt" | head -40 >> "$REPORT"
        echo '            </pre>' >> "$REPORT"
        echo '        </div>' >> "$REPORT"
    fi
    
    # Live Web Hosts & Technologies
    if [[ -f "$OUT/web/live.txt" ]]; then
        echo '        <div class="card">' >> "$REPORT"
        echo '            <h2>🌍 Discovered Live Web Services</h2>' >> "$REPORT"
        echo '            <pre>' >> "$REPORT"
        head -40 "$OUT/web/live.txt" >> "$REPORT"
        echo '            </pre>' >> "$REPORT"
        echo '        </div>' >> "$REPORT"
    fi

    # Subdomains Section
    if [[ -f "$OUT/passive/subdomains.txt" ]]; then
        echo '        <div class="card">' >> "$REPORT"
        echo '            <h2>🌐 Discovered Subdomains</h2>' >> "$REPORT"
        echo '            <pre>' >> "$REPORT"
        head -50 "$OUT/passive/subdomains.txt" >> "$REPORT"
        [[ $subdomains_count -gt 50 ]] && echo "... and $((subdomains_count - 50)) more" >> "$REPORT"
        echo '            </pre>' >> "$REPORT"
        echo '        </div>' >> "$REPORT"
    fi
    
    # Footer & Script
    cat >> "$REPORT" << 'HTMLFOOT'
        <div class="footer">
            <p>Generated by <strong>ReconX v2.0</strong> | Confidential Reconnaissance & Security Audit Report</p>
        </div>
    </div>
    <script>
        function filterTable(tableId, query) {
            const table = document.getElementById(tableId);
            const tr = table.getElementsByTagName("tr");
            const q = query.toLowerCase();
            for (let i = 1; i < tr.length; i++) {
                const text = tr[i].textContent.toLowerCase();
                tr[i].style.display = text.includes(q) ? "" : "none";
            }
        }
    </script>
</body>
</html>
HTMLFOOT

    log_tool "html-export" "success"
    log_success "HTML report exported: $REPORT"
}

# Export JSON Report
export_json_report() {
    local target=$1
    local REPORT_DIR=$2
    local report_timestamp=$3
    local OUT="output/$target"
    local REPORT="$REPORT_DIR/report_${report_timestamp}.json"
    
    log_tool "json-export" "start"
    
    # Collect data
    local subdomains_count=0
    local ports_count=0
    local vuln_critical=0 vuln_high=0 vuln_medium=0 vuln_low=0
    
    [[ -f "$OUT/passive/subdomains.txt" ]] && subdomains_count=$(wc -l < "$OUT/passive/subdomains.txt" 2>/dev/null || echo 0)
    [[ -f "$OUT/active/open_ports_list.txt" ]] && ports_count=$(wc -l < "$OUT/active/open_ports_list.txt" 2>/dev/null || echo 0)
    
    for json_file in "$OUT/vuln"/*.json; do
        [[ -f "$json_file" ]] || continue
        vuln_critical=$((vuln_critical + $(grep -c '"severity":"critical"' "$json_file" 2>/dev/null || true)))
        vuln_high=$((vuln_high + $(grep -c '"severity":"high"' "$json_file" 2>/dev/null || true)))
        vuln_medium=$((vuln_medium + $(grep -c '"severity":"medium"' "$json_file" 2>/dev/null || true)))
        vuln_low=$((vuln_low + $(grep -c '"severity":"low"' "$json_file" 2>/dev/null || true)))
    done
    
    {
        echo "{"
        echo "  \"report\": {"
        echo "    \"title\": \"ReconX Security Assessment Report\","
        echo "    \"target\": \"$target\","
        echo "    \"generated\": \"$(date -Iseconds)\","
        echo "    \"robustness_level\": ${ROBUSTNESS_LEVEL:-3},"
        echo "    \"mode\": \"${MODE:-normal}\""
        echo "  },"
        echo "  \"summary\": {"
        echo "    \"subdomains_count\": $subdomains_count,"
        echo "    \"open_ports_count\": $ports_count,"
        echo "    \"vulnerabilities\": {"
        echo "      \"critical\": $vuln_critical,"
        echo "      \"high\": $vuln_high,"
        echo "      \"medium\": $vuln_medium,"
        echo "      \"low\": $vuln_low,"
        echo "      \"total\": $((vuln_critical + vuln_high + vuln_medium + vuln_low))"
        echo "    }"
        echo "  },"
        
        # Subdomains
        echo "  \"subdomains\": ["
        if [[ -f "$OUT/passive/subdomains.txt" ]]; then
            local first=true
            while IFS= read -r subdomain; do
                [[ "$first" == "true" ]] && first=false || echo ","
                echo -n "    \"$subdomain\""
            done < "$OUT/passive/subdomains.txt"
        fi
        echo ""
        echo "  ],"
        
        # Open Ports
        echo "  \"open_ports\": ["
        if [[ -f "$OUT/active/open_ports_list.txt" ]]; then
            local first=true
            while IFS= read -r port; do
                [[ "$first" == "true" ]] && first=false || echo ","
                echo -n "    $port"
            done < "$OUT/active/open_ports_list.txt"
        fi
        echo ""
        echo "  ],"
        
        # Vulnerabilities
        echo "  \"vulnerabilities\": ["
        local first=true
        for json_file in "$OUT/vuln"/*.json; do
            [[ -f "$json_file" ]] || continue
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                [[ "$first" == "true" ]] && first=false || echo ","
                echo -n "    $line"
            done < "$json_file"
        done
        echo ""
        echo "  ]"
        echo "}"
    } > "$REPORT"
    
    log_tool "json-export" "success"
    log_success "JSON report exported: $REPORT"
}

# Export CSV Report
export_csv_report() {
    local target=$1
    local REPORT_DIR=$2
    local report_timestamp=$3
    local OUT="output/$target"
    
    log_tool "csv-export" "start"
    
    # Vulnerabilities CSV
    local VULN_CSV="$REPORT_DIR/vulnerabilities_${report_timestamp}.csv"
    {
        echo "Severity,Name,Host,Template,Matched,Timestamp"
        for json_file in "$OUT/vuln"/*.json; do
            [[ -f "$json_file" ]] || continue
            [[ "$json_file" == *"consolidated.json"* ]] && continue
            if command -v jq >/dev/null 2>&1; then
                jq -r '. | "\(.info.severity),\"\(.info.name)\",\(.host),\(.template // "N/A"),\(.matched // "N/A"),\(.timestamp // "N/A")"' "$json_file" 2>/dev/null
            elif command -v python3 >/dev/null 2>&1; then
                python3 -c '
import json, sys
for line in open(sys.argv[1]):
    try:
        d = json.loads(line)
        info = d.get("info", {})
        sev = info.get("severity", "")
        name = info.get("name", "N/A").replace("\"", "\"\"")
        host = d.get("host", "N/A")
        tmpl = d.get("template", "N/A")
        matched = d.get("matched", "N/A")
        ts = d.get("timestamp", "N/A")
        print(f"{sev},\"{name}\",{host},{tmpl},{matched},{ts}")
    except Exception: pass
' "$json_file" 2>/dev/null
            fi
        done
    } > "$VULN_CSV"
    
    # Subdomains CSV
    local SUBS_CSV="$REPORT_DIR/subdomains_${report_timestamp}.csv"
    {
        echo "Subdomain,Source"
        if [[ -f "$OUT/passive/subdomains.txt" ]]; then
            while IFS= read -r subdomain; do
                echo "$subdomain,passive_recon"
            done < "$OUT/passive/subdomains.txt"
        fi
    } > "$SUBS_CSV"
    
    # Ports CSV
    local PORTS_CSV="$REPORT_DIR/ports_${report_timestamp}.csv"
    {
        echo "Port,Protocol,Service,Version"
        if [[ -f "$OUT/active/services.txt" ]]; then
            grep -E "^[0-9]+/(tcp|udp)" "$OUT/active/services.txt" | \
            awk -F'[/ ]+' '{print $1","$2","$4","$5}' 2>/dev/null
        fi
    } > "$PORTS_CSV"
    
    log_tool "csv-export" "success"
    log_success "CSV reports exported to: $REPORT_DIR/"
}

# Export PDF Report (requires pandoc and wkhtmltopdf)
export_pdf_report() {
    local target=$1
    local REPORT_DIR=$2
    local report_timestamp=$3
    local OUT="output/$target"
    local MD_REPORT="$REPORT_DIR/report_${report_timestamp}.md"
    local PDF_REPORT="$REPORT_DIR/report_${report_timestamp}.pdf"
    
    log_tool "pdf-export" "start"
    
    # First generate markdown if not exists
    if [[ ! -f "$MD_REPORT" ]]; then
        generate_report "$target"
        MD_REPORT="$REPORT_DIR/report_latest.md"
    fi
    
    # Try pandoc first
    if tool_exists pandoc; then
        pandoc "$MD_REPORT" -o "$PDF_REPORT" \
            --pdf-engine=wkhtmltopdf \
            -V geometry:margin=1in \
            -V fontsize=11pt 2>/dev/null
        
        if [[ -f "$PDF_REPORT" ]]; then
            log_tool "pdf-export" "success"
            log_success "PDF report exported: $PDF_REPORT"
            return 0
        fi
    fi
    
    # Try wkhtmltopdf with HTML
    if tool_exists wkhtmltopdf; then
        local HTML_REPORT="$REPORT_DIR/report_${report_timestamp}.html"
        if [[ ! -f "$HTML_REPORT" ]]; then
            export_html_report "$target" "$REPORT_DIR" "$report_timestamp"
        fi
        
        wkhtmltopdf "$HTML_REPORT" "$PDF_REPORT" 2>/dev/null
        
        if [[ -f "$PDF_REPORT" ]]; then
            log_tool "pdf-export" "success"
            log_success "PDF report exported: $PDF_REPORT"
            return 0
        fi
    fi
    
    log_tool "pdf-export" "fail" "pandoc or wkhtmltopdf not installed"
    log_warn "PDF export requires pandoc or wkhtmltopdf. Install with: apt install pandoc wkhtmltopdf"
}
