import jsPDF from 'jspdf';
import { URLScanResult } from '../types';

export function generatePDFReport(scan: URLScanResult) {
  const doc = new jsPDF();
  const pageWidth = doc.internal.pageSize.getWidth();

  // Header Background
  doc.setFillColor(11, 19, 41);
  doc.rect(0, 0, pageWidth, 40, 'F');

  // Title
  doc.setTextColor(6, 182, 212); // Cyan
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(18);
  doc.text('Phishing URL Analysis & Security Report', 14, 18);

  doc.setFontSize(9);
  doc.setTextColor(148, 163, 184); // Slate 400
  doc.text(`Report ID: ${scan.id} | Generated: ${new Date().toLocaleString()}`, 14, 28);
  doc.text(`ML Classifier Engine: ${scan.ml.model} (v${scan.ml.version})`, 14, 34);

  let y = 48;

  // Overview Box
  const isSafe = scan.riskScore <= 40;
  const isHighRisk = scan.riskScore > 60;
  
  if (isHighRisk) {
    doc.setFillColor(225, 29, 72); // Red
  } else if (isSafe) {
    doc.setFillColor(16, 185, 129); // Green
  } else {
    doc.setFillColor(245, 158, 11); // Yellow
  }

  doc.rect(14, y, pageWidth - 28, 26, 'F');

  doc.setTextColor(255, 255, 255);
  doc.setFontSize(14);
  doc.setFont('helvetica', 'bold');
  doc.text(`Threat Level: ${scan.riskLevel.toUpperCase()} (${scan.riskScore}/100 Risk Score)`, 20, y + 12);

  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  doc.text(`Security Grade: ${scan.grade} | Confidence: ${scan.ml.confidence} | Scan Time: ${scan.scanTime}`, 20, y + 20);

  y += 36;

  // URL Details
  doc.setTextColor(30, 41, 59);
  doc.setFontSize(12);
  doc.setFont('helvetica', 'bold');
  doc.text('Target URL & Domain Analysis', 14, y);
  y += 6;

  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(51, 65, 85);
  doc.text(`URL: ${scan.url}`, 14, y); y += 6;
  doc.text(`Hostname: ${scan.domain.hostname} (TLD: ${scan.domain.tld})`, 14, y); y += 6;
  doc.text(`IP Address: ${scan.domain.ip} | Country: ${scan.domain.country}`, 14, y); y += 6;
  doc.text(`Registrar: ${scan.domain.registrar} | Domain Age: ${scan.domain.domain_age_days} days`, 14, y); y += 6;
  doc.text(`SSL Encryption: ${scan.ssl.enabled ? 'HTTPS Enabled (' + scan.ssl.issuer + ')' : 'Insecure HTTP'}`, 14, y); y += 10;

  // Threat Indicators Checklist
  doc.setFontSize(12);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(30, 41, 59);
  doc.text('Security Threat Indicators', 14, y);
  y += 6;

  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');

  const threatsList = [
    ['IP Address Hostname', scan.threats.ip_address_url ? 'DETECTED (HIGH RISK)' : 'PASS'],
    ['URL Shortener Service', scan.threats.url_shortener ? 'DETECTED' : 'PASS'],
    ['Suspicious Keywords', scan.threats.suspicious_keywords ? 'DETECTED' : 'PASS'],
    ['Homograph / Punycode Attack', scan.threats.homograph_attack ? 'DETECTED (CRITICAL)' : 'PASS'],
    ['Typosquatting & Brand Impersonation', scan.threats.typosquatting_brand ? 'DETECTED (CRITICAL)' : 'PASS'],
    ['Excessive Subdomains', scan.threats.subdomains_excessive ? 'DETECTED' : 'PASS']
  ];

  for (const [title, status] of threatsList) {
    if (status.includes('DETECTED')) {
      doc.setTextColor(225, 29, 72);
      doc.setFont('helvetica', 'bold');
    } else {
      doc.setTextColor(16, 185, 129);
      doc.setFont('helvetica', 'normal');
    }
    doc.text(`• ${title}: ${status}`, 18, y);
    y += 5;
  }

  y += 6;

  // Reasons & Analysis
  doc.setFontSize(12);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(30, 41, 59);
  doc.text('Detected Vulnerabilities & Machine Learning Reasons', 14, y);
  y += 6;

  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(51, 65, 85);

  for (const reason of scan.reasons) {
    const lines = doc.splitTextToSize(`• ${reason}`, pageWidth - 32);
    doc.text(lines, 18, y);
    y += lines.length * 5;
  }

  y += 6;

  // Recommendations
  doc.setFontSize(12);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(30, 41, 59);
  doc.text('Actionable Security Recommendations', 14, y);
  y += 6;

  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(51, 65, 85);

  for (const rec of scan.recommendations) {
    const lines = doc.splitTextToSize(`• ${rec}`, pageWidth - 32);
    doc.text(lines, 18, y);
    y += lines.length * 5;
  }

  // Footer for Page 1
  doc.setFontSize(8);
  doc.setTextColor(148, 163, 184);
  doc.text('Enterprise Phishing URL Detection & Cyber Security Platform | Page 1 of 2', 14, doc.internal.pageSize.getHeight() - 10);

  // --- PAGE 2: 32-Point Granular Website Checking Parameters Ledger ---
  if (scan.parameters && scan.parameters.length > 0) {
    doc.addPage();
    const pageHeight = doc.internal.pageSize.getHeight();

    // Page 2 Header Banner
    doc.setFillColor(11, 19, 41);
    doc.rect(0, 0, pageWidth, 32, 'F');

    doc.setTextColor(6, 182, 212); // Cyan
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(15);
    doc.text('Granular Website Checking Parameters Ledger (32 Checks)', 14, 15);

    const scanParameters = Array.isArray(scan.parameters) ? scan.parameters : [];
    doc.setFontSize(8.5);
    doc.setTextColor(148, 163, 184);
    const passCount = scan.parameterSummary?.passed ?? scanParameters.filter(p => p.status === 'Pass').length;
    const warnCount = scan.parameterSummary?.warnings ?? scanParameters.filter(p => p.status === 'Warning').length;
    const failCount = scan.parameterSummary?.failed ?? scanParameters.filter(p => p.status === 'Fail').length;
    doc.text(`Target URL: ${scan.url.substring(0, 75)} | Passed: ${passCount} | Warnings: ${warnCount} | Failed: ${failCount}`, 14, 25);

    let py = 42;

    // Table Header
    doc.setFillColor(241, 245, 249);
    doc.rect(14, py - 4, pageWidth - 28, 8, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.5);
    doc.setTextColor(15, 23, 42);

    doc.text('#', 16, py + 1.5);
    doc.text('CHECK / PARAMETER', 24, py + 1.5);
    doc.text('CATEGORY', 80, py + 1.5);
    doc.text('INSPECTED VALUE', 126, py + 1.5);
    doc.text('STATUS', 162, py + 1.5);
    doc.text('SEVERITY', 184, py + 1.5);

    py += 8;

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7);

    scanParameters.forEach((param, idx) => {
      if (py > pageHeight - 18) {
        doc.addPage();
        py = 20;
      }

      // Alternate row tint
      if (idx % 2 === 1) {
        doc.setFillColor(248, 250, 252);
        doc.rect(14, py - 3.5, pageWidth - 28, 6.5, 'F');
      }

      doc.setTextColor(71, 85, 105);
      doc.text(`${idx + 1}`, 16, py + 1);

      doc.setFont('helvetica', 'bold');
      doc.setTextColor(15, 23, 42);
      const trimmedName = param.name.length > 28 ? param.name.substring(0, 27) + '...' : param.name;
      doc.text(trimmedName, 24, py + 1);

      doc.setFont('helvetica', 'normal');
      doc.setTextColor(100, 116, 139);
      const catShort = param.category.replace('& URL Anatomy', '').replace('& Obfuscation', '').replace('& Host Reputation', '').replace('& Transport Security', '').replace('& Social Engineering', '').trim();
      doc.text(catShort, 80, py + 1);

      doc.setTextColor(30, 41, 59);
      const valStr = String(param.displayValue).length > 20 ? String(param.displayValue).substring(0, 19) + '...' : String(param.displayValue);
      doc.text(valStr, 126, py + 1);

      // Status with color
      if (param.status === 'Pass') {
        doc.setTextColor(16, 185, 129); // green
      } else if (param.status === 'Warning') {
        doc.setTextColor(217, 119, 6); // amber
      } else {
        doc.setTextColor(225, 29, 72); // rose
      }
      doc.setFont('helvetica', 'bold');
      doc.text(param.status.toUpperCase(), 162, py + 1);

      doc.setTextColor(param.severity === 'Critical' ? 225 : (param.severity === 'High' ? 190 : 100), 50, 50);
      doc.setFont('helvetica', 'normal');
      doc.text(param.severity, 184, py + 1);

      py += 6.5;
    });

    // Page 2 Footer
    doc.setFontSize(8);
    doc.setTextColor(148, 163, 184);
    doc.text('PhishGuard Comprehensive Heuristic Parameter Audit | Page 2 of 2', 14, doc.internal.pageSize.getHeight() - 10);
  }

  // Save PDF
  doc.save(`Phishing_Report_${scan.id}.pdf`);
}
