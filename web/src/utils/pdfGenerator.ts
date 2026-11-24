import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import type { TestRun } from '../types';
import { interpretReport, severityPdf } from './reportInsights';

type JsPDFWithAutoTable = jsPDF & { lastAutoTable: { finalY: number } };

function autoTableFinalY(doc: jsPDF): number {
  return (doc as JsPDFWithAutoTable).lastAutoTable.finalY;
}

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

  currentY = autoTableFinalY(doc) + 10;

  // Section 2: Executive Summary
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(14);
  doc.setTextColor(31, 41, 55);
  doc.text('2. Executive Summary & Findings', 15, currentY);
  currentY += 6;

  // The assessment (title / severity / summary / impact / recommendation) comes
  // from the shared interpretReport helper so the PDF and the on-screen report
  // always tell the same story and every scenario is covered.
  const insight = interpretReport(test);
  const palette = severityPdf[insight.severity];
  const alertTitle = `${palette.label} — ${insight.title}`;

  const boxWidth = pageWidth - 30;
  const textWidth = boxWidth - 10;
  const summaryLines = doc.splitTextToSize(insight.summary, textWidth);
  const impactLines = doc.splitTextToSize(`Impact: ${insight.impact}`, textWidth);
  const recommendationLines = doc.splitTextToSize(`Recommendation: ${insight.recommendation}`, textWidth);
  const bodyLineCount = summaryLines.length + impactLines.length + recommendationLines.length;
  // title row + spacing between the three blocks + line heights
  const boxHeight = 10 + bodyLineCount * 4.3 + 6;

  // Page-break guard so the whole assessment box stays together.
  if (currentY + boxHeight > 275) {
    doc.addPage();
    currentY = 15;
  }

  doc.setFillColor(palette.bg[0], palette.bg[1], palette.bg[2]);
  doc.rect(15, currentY, boxWidth, boxHeight, 'F');

  doc.setFillColor(palette.border[0], palette.border[1], palette.border[2]);
  doc.rect(15, currentY, 2, boxHeight, 'F');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(palette.title[0], palette.title[1], palette.title[2]);
  doc.text(alertTitle, 20, currentY + 6);

  let textY = currentY + 12;
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(palette.text[0], palette.text[1], palette.text[2]);
  doc.text(summaryLines, 20, textY);
  textY += summaryLines.length * 4.3 + 1.5;

  doc.setFont('helvetica', 'bold');
  doc.text(impactLines, 20, textY);
  textY += impactLines.length * 4.3 + 1.5;
  doc.text(recommendationLines, 20, textY);

  currentY += boxHeight + 10;

  // Section 3: Configuration Profile
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(14);
  doc.setTextColor(31, 41, 55);
  doc.text('3. Configuration Profile', 15, currentY);
  currentY += 4;

  const configBody = Object.entries(test.config || {}).map(([k, v]) => [
    k.replace(/_/g, ' '),
    typeof v === 'object' && v !== null ? (Array.isArray(v) ? v.join(', ') : JSON.stringify(v)) : String(v)
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

  currentY = autoTableFinalY(doc) + 10;

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
        typeof v === 'number' && k.includes('latency')
          ? `${v.toFixed(2)} ms`
          : typeof v === 'object' && v !== null
          ? (Array.isArray(v) ? v.join(', ') : JSON.stringify(v))
          : String(v)
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

    currentY = autoTableFinalY(doc) + 10;
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
