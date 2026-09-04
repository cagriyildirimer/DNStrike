import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import type { TestRun } from '../types';

export function generatePdfReport(test: TestRun) {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4'
  });

  const score = test.resilience_score ?? 0;
  const pageWidth = doc.internal.pageSize.getWidth();
  let currentY = 15;

  // Header Title
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(22);
  doc.setTextColor(17, 24, 39); // #111827
  doc.text('DNStrike Assessment Report', 15, currentY);
  currentY += 8;

  // Subheader Info
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(10);
  doc.setTextColor(75, 85, 99); // #4b5563
  doc.text(`Report ID: #${test.id}`, 15, currentY);
  doc.text(`Date: ${new Date().toLocaleDateString()}`, pageWidth - 15, currentY, { align: 'right' });
  currentY += 6;

  // Divider Line
  doc.setDrawColor(229, 231, 235); // #e5e7eb
  doc.setLineWidth(0.5);
  doc.line(15, currentY, pageWidth - 15, currentY);
  currentY += 10;

  // Section 1: Assessment Scope
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(14);
  doc.setTextColor(31, 41, 55);
  doc.text('1. Assessment Scope', 15, currentY);
  currentY += 4;

  autoTable(doc, {
    startY: currentY,
    theme: 'plain',
    styles: { fontSize: 9, cellPadding: 2, textColor: [31, 41, 55] },
    columnStyles: {
      0: { fontStyle: 'bold', textColor: [107, 114, 128], cellWidth: 40 },
      1: { cellWidth: 'auto' }
    },
    body: [
      ['Target ID:', String(test.target_id)],
      ['Scenario:', String(test.scenario)],
      ['Status:', String(test.status)],
      ['Started At:', test.started_at ? new Date(test.started_at).toLocaleString() : '-'],
      ['Finished At:', test.finished_at ? new Date(test.finished_at).toLocaleString() : '-']
    ],
    margin: { left: 15, right: 15 }
  });

  // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-explicit-any
  currentY = (doc as any).lastAutoTable.finalY + 10;

  // Section 2: Executive Summary
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(14);
  doc.setTextColor(31, 41, 55);
  doc.text('2. Executive Summary & Findings', 15, currentY);
  currentY += 6;

  let alertBg = [240, 253, 244]; // green light
  let alertBorder = [34, 197, 94];
  let alertTitleColor = [21, 128, 61];
  let alertTextColor = [20, 83, 45];
  let alertTitle = 'SECURE CONFIGURATION';
  let alertText = 'The DNS infrastructure correctly refused unauthorized recursion and zone transfers. The configuration follows security best practices.';

  if (test.scenario === 'subdomain-takeover') {
    const vulnCount = Number(test.result?.vulnerable_count ?? 0);
    if (vulnCount > 0) {
      alertBg = [254, 242, 242];
      alertBorder = [239, 68, 68];
      alertTitleColor = [185, 28, 28];
      alertTextColor = [127, 29, 29];
      alertTitle = 'HIGH RISK (SUBDOMAINS VULNERABLE TO TAKEOVER)';
      alertText = `Found ${vulnCount} dangling CNAME records pointing to decommissioned cloud providers (AWS, GitHub Pages, Heroku, Azure). Immediate action required: remove orphaned CNAMEs or claim backend resources.`;
    } else {
      alertTitle = 'NO DANGLING CNAMEs DETECTED';
      alertText = 'All scanned CNAME records resolve safely to active backend targets. No subdomain takeover vectors detected.';
    }
  } else if (test.scenario === 'dns-fuzzing') {
    if (test.result?.target_crashed === true) {
      alertBg = [254, 242, 242];
      alertBorder = [239, 68, 68];
      alertTitleColor = [185, 28, 28];
      alertTextColor = [127, 29, 29];
      alertTitle = 'CRITICAL VULNERABILITY (SERVER PROCESS CRASH)';
      alertText = 'The DNS server crashed or froze during malformed packet fuzzing vectors. Upgrade DNS software and enforce strict UDP packet parsing checks.';
    } else {
      alertTitle = 'EXCELLENT FUZZING RESILIENCE';
      alertText = 'The DNS server successfully handled malformed packet vectors without process crashes or service degradation.';
    }
  } else if (test.scenario === 'zone-transfer-audit') {
    const leaked = Number(test.result?.total_leaked_records ?? 0);
    if (leaked > 0) {
      alertBg = [254, 242, 242];
      alertBorder = [239, 68, 68];
      alertTitleColor = [185, 28, 28];
      alertTextColor = [127, 29, 29];
      alertTitle = 'CRITICAL ZONE TRANSFER LEAK DETECTED';
      alertText = `The DNS server permitted an unauthorized AXFR full zone transfer and siphoned ${leaked} domain records. Disable AXFR globally or restrict transfers exclusively to secondary nameserver IPs.`;
    } else {
      alertTitle = 'SECURE ZONE TRANSFER POSTURE';
      alertText = 'The DNS server correctly refused unauthorized AXFR zone transfer requests. Domain record database remains protected.';
    }
  } else if (test.scenario === 'tcp-slowloris') {
    if (test.result?.legitimate_tcp_served === false) {
      alertBg = [254, 242, 242];
      alertBorder = [239, 68, 68];
      alertTitleColor = [185, 28, 28];
      alertTextColor = [127, 29, 29];
      alertTitle = 'HIGH VULNERABILITY (TCP DoS DETECTED)';
      alertText = 'The DNS server failed to serve legitimate TCP queries while TCP sockets were held open. The server lacks TCP socket connection pooling or idle timeout protection.';
    } else {
      alertTitle = 'EXCELLENT TCP RESILIENCE';
      alertText = 'The DNS server successfully served legitimate TCP queries under socket exhaustion pressure.';
    }
  } else if (test.scenario === 'security-audit') {
    if (score < 50) {
      alertBg = [254, 242, 242];
      alertBorder = [239, 68, 68];
      alertTitleColor = [185, 28, 28];
      alertTextColor = [127, 29, 29];
      alertTitle = 'CRITICAL VULNERABILITY DETECTED';
      alertText = 'The DNS server is severely misconfigured. Open Recursion or Zone Transfer (AXFR) vulnerabilities were found. Immediate remediation is required: Restrict recursion to trusted networks only and disable AXFR transfers globally.';
    } else if (score < 90) {
      alertBg = [255, 251, 235];
      alertBorder = [245, 158, 11];
      alertTitleColor = [180, 83, 9];
      alertTextColor = [146, 64, 14];
      alertTitle = 'SECURITY WARNING';
      alertText = 'Some potential misconfigurations or information leaks were detected. Review specific findings to ensure sensitive records (like ANY queries) are protected.';
    }
  } else {
    const loss = test.result?.loss !== undefined ? Number(test.result.loss) : 0;
    if (loss > 0) {
      alertBg = [254, 242, 242];
      alertBorder = [239, 68, 68];
      alertTitleColor = [185, 28, 28];
      alertTextColor = [127, 29, 29];
      alertTitle = 'CAPACITY EXCEEDED (PACKET LOSS)';
      alertText = `The server failed to respond to all queries. A loss rate of ${loss} was detected. Packet loss indicates UDP packet drops due to resource exhaustion or rate-limiting.`;
    } else if (score < 100) {
      alertBg = [255, 251, 235];
      alertBorder = [245, 158, 11];
      alertTitleColor = [180, 83, 9];
      alertTextColor = [146, 64, 14];
      alertTitle = 'HIGH LATENCY DETECTED';
      alertText = 'The server processed requests, but response times degraded significantly under load, leading to slower resolution times during traffic spikes.';
    } else {
      alertTitle = 'EXCELLENT RESILIENCE';
      alertText = 'The infrastructure handled the requested Queries Per Second (QPS) flawlessly with zero packet loss and optimal latency.';
    }
  }

  // Draw Alert Box
  const boxWidth = pageWidth - 30;
  const splitText = doc.splitTextToSize(alertText, boxWidth - 10);
  const boxHeight = 12 + (splitText.length * 4.5);

  doc.setFillColor(alertBg[0], alertBg[1], alertBg[2]);
  doc.rect(15, currentY, boxWidth, boxHeight, 'F');
  
  doc.setFillColor(alertBorder[0], alertBorder[1], alertBorder[2]);
  doc.rect(15, currentY, 2, boxHeight, 'F');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(alertTitleColor[0], alertTitleColor[1], alertTitleColor[2]);
  doc.text(alertTitle, 20, currentY + 6);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(alertTextColor[0], alertTextColor[1], alertTextColor[2]);
  doc.text(splitText, 20, currentY + 11);

  currentY += boxHeight + 10;

  // Section 3: Configuration Profile
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(14);
  doc.setTextColor(31, 41, 55);
  doc.text('3. Configuration Profile', 15, currentY);
  currentY += 4;

  const configBody = Object.entries(test.config || {}).map(([k, v]) => [
    k.replace(/_/g, ' '),
    String(v)
  ]);

  autoTable(doc, {
    startY: currentY,
    theme: 'grid',
    headStyles: { fillColor: [243, 244, 246], textColor: [55, 65, 81], fontStyle: 'bold' },
    styles: { fontSize: 8, cellPadding: 2.5, textColor: [31, 41, 55] },
    columnStyles: {
      0: { fontStyle: 'bold', cellWidth: 60, fillColor: [249, 250, 251] },
      1: { cellWidth: 'auto' }
    },
    body: configBody.length > 0 ? configBody : [['Status', 'No configuration parameters provided']],
    margin: { left: 15, right: 15 }
  });

  // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-explicit-any
  currentY = (doc as any).lastAutoTable.finalY + 10;

  // Section 4: Detailed Execution Results
  if (test.result && Object.keys(test.result).length > 0) {
    if (currentY > 230) {
      doc.addPage();
      currentY = 15;
    }

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(14);
    doc.setTextColor(31, 41, 55);
    doc.text('4. Execution Results', 15, currentY);
    currentY += 4;

    if (test.result.amplification_results && Array.isArray(test.result.amplification_results)) {
      const ampBody = (test.result.amplification_results as Array<Record<string, unknown>>).map(item => [
        `${String(item.query_type)} ${item.edns0 ? '(EDNS0)' : ''}`,
        `${String(item.request_bytes)} B`,
        `${String(item.response_bytes)} B`,
        `${String(item.amplification)}x`,
        String(item.rcode),
        String(item.status)
      ]);

      autoTable(doc, {
        startY: currentY,
        theme: 'grid',
        head: [['Query Type', 'Req Size', 'Resp Size', 'Multiplier', 'RCode', 'Status']],
        headStyles: { fillColor: [243, 244, 246], textColor: [55, 65, 81], fontStyle: 'bold' },
        styles: { fontSize: 8, cellPadding: 2.5, textColor: [31, 41, 55] },
        body: ampBody,
        margin: { left: 15, right: 15 }
      });
    } else {
      const resultBody = Object.entries(test.result).map(([k, v]) => [
        k.replace(/_/g, ' '),
        typeof v === 'number' && k.includes('latency') ? `${v.toFixed(2)} ms` : String(v)
      ]);

      autoTable(doc, {
        startY: currentY,
        theme: 'grid',
        headStyles: { fillColor: [243, 244, 246], textColor: [55, 65, 81], fontStyle: 'bold' },
        styles: { fontSize: 8, cellPadding: 2.5, textColor: [31, 41, 55] },
        columnStyles: {
          0: { fontStyle: 'bold', cellWidth: 60, fillColor: [249, 250, 251] },
          1: { fontStyle: 'bold', cellWidth: 'auto' }
        },
        body: resultBody,
        margin: { left: 15, right: 15 }
      });
    }

    // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-explicit-any
    currentY = (doc as any).lastAutoTable.finalY + 10;
  }

  // Score Footer Box
  if (currentY > 250) {
    doc.addPage();
    currentY = 15;
  }

  doc.setFillColor(243, 244, 246);
  doc.rect(15, currentY, boxWidth, 14, 'F');

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(10);
  doc.setTextColor(75, 85, 99);
  doc.text('Overall Resilience Score:', 20, currentY + 9);

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(12);
  const scoreTextColor = score >= 90 ? [22, 163, 74] : score >= 50 ? [217, 119, 6] : [220, 38, 38];
  doc.setTextColor(scoreTextColor[0], scoreTextColor[1], scoreTextColor[2]);
  doc.text(test.status === 'COMPLETED' ? `${score} / 100` : 'N/A', pageWidth - 20, currentY + 9, { align: 'right' });

  // Add Page Numbers
  const totalPages = doc.internal.pages.length - 1;
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(156, 163, 175);
    doc.text(`Page ${i} of ${totalPages}`, pageWidth / 2, 287, { align: 'center' });
    doc.text('Generated by DNStrike Automated Assessment Framework', 15, 287);
  }

  // Direct Download Trigger
  doc.save(`DNStrike-Report-${test.id}.pdf`);
}
