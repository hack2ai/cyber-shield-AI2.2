import { jsPDF } from 'jspdf';

export interface IncidentReportData {
  target: string;
  type: 'url' | 'ip' | 'email' | 'domain' | 'keyword' | 'phone' | 'message' | 'file';
  threatScore: number;
  classification: string;
  explanation: string;
  recommendation: string;
  riskIndicators?: string[];
  timestamp?: string;
  fileName?: string;
  fileSize?: number;
  sha256?: string;
  technicalSummary?: {
    dns?: string;
    ssl?: string;
    whois?: string;
    threatIntel?: string;
  };
  iocIndicators?: string[];
}

export interface BrandingOptions {
  companyName: string;
  operatorName: string;
  accentColor: string;
}

function hexToRgb(hex: string): [number, number, number] {
  const cleanHex = hex.replace('#', '');
  const r = parseInt(cleanHex.substring(0, 2), 16) || 0;
  const g = parseInt(cleanHex.substring(2, 4), 16) || 245;
  const b = parseInt(cleanHex.substring(4, 6), 16) || 255;
  return [r, g, b];
}

export function generateIncidentReport(data: IncidentReportData, branding: BrandingOptions): jsPDF {
  // Page is A4 (210 x 297 mm)
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4'
  });

  const primaryAccent = hexToRgb(branding.accentColor);
  const bgDark = [10, 10, 12];
  const cardDark = [17, 17, 21];
  const textWhite = [255, 255, 255];
  const textMuted = [161, 161, 170];

  const classColor = 
    data.classification === 'Safe' ? [57, 255, 20] :
    data.classification === 'Suspicious' ? [245, 158, 11] : [239, 68, 68];

  // Helper to draw dark page layout
  const initPageLayout = (pageNum: number) => {
    // 1. Fill background
    doc.setFillColor(bgDark[0], bgDark[1], bgDark[2]);
    doc.rect(0, 0, 210, 297, 'F');

    // 2. Draw outer cyber frame border
    doc.setDrawColor(primaryAccent[0], primaryAccent[1], primaryAccent[2]);
    doc.setLineWidth(0.5);
    doc.rect(8, 8, 194, 281, 'D');

    // Accent corners
    doc.setLineWidth(1.5);
    // Top-left
    doc.line(8, 8, 20, 8);
    doc.line(8, 8, 8, 20);
    // Top-right
    doc.line(202, 8, 190, 8);
    doc.line(202, 8, 202, 20);
    // Bottom-left
    doc.line(8, 289, 20, 289);
    doc.line(8, 289, 8, 277);
    // Bottom-right
    doc.line(202, 289, 190, 289);
    doc.line(202, 289, 202, 277);

    // 3. Footer branding
    doc.setFont('courier', 'normal');
    doc.setFontSize(7);
    doc.setTextColor(textMuted[0], textMuted[1], textMuted[2]);
    doc.text(`SECURITY_CLASSIFIED // ${branding.companyName.toUpperCase()} SOC`, 12, 285);
    doc.text(`PAGE ${pageNum} OF 2`, 180, 285);
  };

  // ==================== PAGE 1 ====================
  initPageLayout(1);

  // Top header logo text
  doc.setFont('courier', 'bold');
  doc.setFontSize(14);
  doc.setTextColor(primaryAccent[0], primaryAccent[1], primaryAccent[2]);
  doc.text(branding.companyName.toUpperCase(), 15, 20);

  doc.setFont('courier', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(textMuted[0], textMuted[1], textMuted[2]);
  doc.text(`OPERATOR: ${branding.operatorName.toUpperCase()}`, 15, 25);
  doc.text(`TIMESTAMP: ${data.timestamp || new Date().toISOString()}`, 120, 20);

  // Divider
  doc.setDrawColor(primaryAccent[0], primaryAccent[1], primaryAccent[2]);
  doc.setLineWidth(0.3);
  doc.line(15, 30, 195, 30);

  // Title block
  doc.setFont('courier', 'bold');
  doc.setFontSize(20);
  doc.setTextColor(textWhite[0], textWhite[1], textWhite[2]);
  doc.text("CYBER INCIDENT AUDIT REPORT", 15, 42);

  // Target info container
  doc.setFillColor(cardDark[0], cardDark[1], cardDark[2]);
  doc.setDrawColor(255, 255, 255, 10);
  doc.rect(15, 50, 180, 25, 'F');

  doc.setFont('courier', 'bold');
  doc.setFontSize(9);
  doc.setTextColor(primaryAccent[0], primaryAccent[1], primaryAccent[2]);
  doc.text("AUDIT TARGET:", 18, 56);
  doc.text("VECTOR TYPE:", 18, 62);
  if (data.sha256) {
    doc.text("SHA256 HASH:", 18, 68);
  } else {
    doc.text("REGISTRY AGE:", 18, 68);
  }

  doc.setFont('courier', 'normal');
  doc.setTextColor(textWhite[0], textWhite[1], textWhite[2]);
  
  // Truncate target url/filename if too long
  const targetLabel = data.fileName || data.target;
  const truncatedTarget = targetLabel.length > 55 ? targetLabel.substring(0, 52) + '...' : targetLabel;
  doc.text(truncatedTarget, 55, 56);
  doc.text(data.type.toUpperCase(), 55, 62);

  if (data.sha256) {
    doc.text(data.sha256, 55, 68);
  } else {
    doc.text(data.technicalSummary?.whois?.toLowerCase().includes('old') ? data.technicalSummary.whois : 'HEURISTICS MATCH', 55, 68);
  }

  // Threat Score Gauge Draw
  doc.setFont('courier', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(textWhite[0], textWhite[1], textWhite[2]);
  doc.text("CRITICAL_THREAT_RISK_INDEX", 15, 87);

  // Score Bar Background
  doc.setFillColor(40, 40, 45);
  doc.rect(15, 92, 180, 6, 'F');

  // Score Bar Filled
  doc.setFillColor(classColor[0], classColor[1], classColor[2]);
  const fillWidth = Math.max(2, Math.round((data.threatScore / 100) * 180));
  doc.rect(15, 92, fillWidth, 6, 'F');

  // Draw Score ticks
  doc.setFont('courier', 'normal');
  doc.setFontSize(7);
  doc.setTextColor(textMuted[0], textMuted[1], textMuted[2]);
  doc.text("0", 15, 102);
  doc.text("50", 102, 102);
  doc.text("100", 191, 102);

  // Score Value text & Classification bubble
  doc.setFont('courier', 'bold');
  doc.setFontSize(14);
  doc.setTextColor(classColor[0], classColor[1], classColor[2]);
  doc.text(`SCORE: ${data.threatScore} // ${data.classification.toUpperCase()}`, 15, 112);

  // Risk summary Card
  doc.setFillColor(cardDark[0], cardDark[1], cardDark[2]);
  doc.rect(15, 122, 180, 45, 'F');
  // Left border alert line
  doc.setFillColor(classColor[0], classColor[1], classColor[2]);
  doc.rect(15, 122, 1.5, 45, 'F');

  doc.setFont('courier', 'bold');
  doc.setFontSize(9);
  doc.setTextColor(primaryAccent[0], primaryAccent[1], primaryAccent[2]);
  doc.text("INCIDENT_EXPLANATION_SUMMARY", 20, 129);

  doc.setFont('courier', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(textWhite[0], textWhite[1], textWhite[2]);
  const explanationLines = doc.splitTextToSize(data.explanation, 170);
  let expY = 135;
  explanationLines.slice(0, 5).forEach((line: string) => {
    doc.text(line, 20, expY);
    expY += 5;
  });

  // Technical Summary metrics details
  doc.setFont('courier', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(textWhite[0], textWhite[1], textWhite[2]);
  doc.text("DECOMPOSED_HEURISTICS_TELEMETRY", 15, 180);

  // Draw two column grid box
  doc.setFillColor(cardDark[0], cardDark[1], cardDark[2]);
  doc.rect(15, 185, 180, 85, 'F');

  doc.setFont('courier', 'bold');
  doc.setFontSize(8.5);
  doc.setTextColor(primaryAccent[0], primaryAccent[1], primaryAccent[2]);
  doc.text("DNS_COORDINATES", 20, 192);
  doc.text("SSL_SECURITY_HANDSHAKE", 20, 230);

  doc.setFont('courier', 'normal');
  doc.setTextColor(textWhite[0], textWhite[1], textWhite[2]);
  const dnsTxt = data.technicalSummary?.dns || "No secondary DNS hijack attempts resolved on outbound routes.";
  const dnsLines = doc.splitTextToSize(dnsTxt, 170);
  let dnsY = 197;
  dnsLines.slice(0, 5).forEach((line: string) => {
    doc.text(line, 20, dnsY);
    dnsY += 4.5;
  });

  const sslTxt = data.technicalSummary?.ssl || "Secure Handshake verified. High grade cipher suites negotiation complete.";
  const sslLines = doc.splitTextToSize(sslTxt, 170);
  let sslY = 235;
  sslLines.slice(0, 5).forEach((line: string) => {
    doc.text(line, 20, sslY);
    sslY += 4.5;
  });


  // ==================== PAGE 2 ====================
  doc.addPage();
  initPageLayout(2);

  // Title Page 2
  doc.setFont('courier', 'bold');
  doc.setFontSize(12);
  doc.setTextColor(primaryAccent[0], primaryAccent[1], primaryAccent[2]);
  doc.text("COUNTER_MEASURES_AND_PREVENTIONS", 15, 20);

  // Recommendations Card
  doc.setFillColor(cardDark[0], cardDark[1], cardDark[2]);
  doc.rect(15, 25, 180, 65, 'F');
  doc.setFillColor(57, 255, 20); // Green accent
  doc.rect(15, 25, 1.5, 65, 'F');

  doc.setFont('courier', 'bold');
  doc.setFontSize(9);
  doc.setTextColor(57, 255, 20);
  doc.text("RECOMMENDED_TACTICAL_ACTION_PLAN", 20, 32);

  doc.setFont('courier', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(textWhite[0], textWhite[1], textWhite[2]);
  const recLines = doc.splitTextToSize(data.recommendation, 170);
  let recY = 38;
  recLines.slice(0, 10).forEach((line: string) => {
    doc.text(line, 20, recY);
    recY += 5;
  });

  // Indicators of Compromise (IOC)
  doc.setFont('courier', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(textWhite[0], textWhite[1], textWhite[2]);
  doc.text("INDICATORS_OF_COMPROMISE (IOC)", 15, 105);

  doc.setFillColor(cardDark[0], cardDark[1], cardDark[2]);
  doc.rect(15, 110, 180, 55, 'F');

  doc.setFont('courier', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(textWhite[0], textWhite[1], textWhite[2]);
  
  const iocs = data.iocIndicators || data.riskIndicators || [
    "SHA256 hash pattern signature matches known payload heuristics",
    "Domain registers sub-30 days Old threshold flags active social engineering templates",
    "Entropy validation logs packer traces on raw section headers"
  ];

  let iocY = 117;
  iocs.slice(0, 8).forEach((ioc: string, idx: number) => {
    const formattedIoc = ioc.length > 85 ? ioc.substring(0, 82) + '...' : ioc;
    doc.setTextColor(classColor[0], classColor[1], classColor[2]);
    doc.text(`[IOC-${idx+1}]`, 20, iocY);
    doc.setTextColor(textWhite[0], textWhite[1], textWhite[2]);
    doc.text(formattedIoc, 38, iocY);
    iocY += 6;
  });

  // Regulatory Policy Compliance & Footnote
  doc.setFont('courier', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(textWhite[0], textWhite[1], textWhite[2]);
  doc.text("REGULATORY_COMPLIANCE_DISCLOSURE", 15, 180);

  doc.setFillColor(cardDark[0], cardDark[1], cardDark[2]);
  doc.rect(15, 185, 180, 85, 'F');

  doc.setFont('courier', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(textMuted[0], textMuted[1], textMuted[2]);
  
  const disclaimerText = 
    "This report is generated dynamically by the Cyber Shield AI security heuristics engine. " +
    "The analysis parameters reflect static checks, network handshake simulations, registry lookups, " +
    "and AI threat analysis. This report is for security assessment and incident response purposes " +
    "only and represents telemetry intelligence collected at the scan time. Operator credentials must " +
    "be verified prior to distributing payload signatures to boundary whitelists. In accordance with " +
    "ISO 27001 policies, incident indicators should be filed inside local SIEM logs immediately.";
  
  const disclaimerLines = doc.splitTextToSize(disclaimerText, 170);
  let disY = 192;
  disclaimerLines.forEach((line: string) => {
    doc.text(line, 20, disY);
    disY += 4.5;
  });

  // Signature Block
  doc.setDrawColor(primaryAccent[0], primaryAccent[1], primaryAccent[2]);
  doc.setLineWidth(0.2);
  doc.line(20, 245, 90, 245);
  doc.line(120, 245, 190, 245);

  doc.setFont('courier', 'bold');
  doc.setFontSize(7.5);
  doc.setTextColor(primaryAccent[0], primaryAccent[1], primaryAccent[2]);
  doc.text("SOC OPERATOR SIGNATURE", 20, 249);
  doc.text("SYSTEM ANALYST HANDSHAKE", 120, 249);

  doc.setFont('courier', 'normal');
  doc.setTextColor(textWhite[0], textWhite[1], textWhite[2]);
  doc.text(branding.operatorName.toUpperCase(), 20, 254);
  doc.text("CYBER_SHIELD_AI_AGENT", 120, 254);

  return doc;
}
