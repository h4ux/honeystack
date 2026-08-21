/* Minimal PDF writer: enough of the spec to emit a multi-page text report
   with optional JPEG charts. No dependencies, so the dashboard stays a
   plain static site that can be hosted anywhere. */
(function () {
  const PAGE_W = 595.28; // A4 points
  const PAGE_H = 841.89;
  const MARGIN = 40;

  function escapeText(s) {
    return String(s == null ? '' : s)
      .replace(/\\/g, '\\\\')
      .replace(/\(/g, '\\(')
      .replace(/\)/g, '\\)')
      // WinAnsi-ish: drop anything the base14 fonts cannot show
      .replace(/[^\x20-\x7E]/g, '?');
  }

  class PdfDoc {
    constructor(title) {
      this.title = title || 'Report';
      this.pages = [];
      this.images = [];
      this.newPage();
    }

    newPage() {
      this.current = { ops: [], y: PAGE_H - MARGIN };
      this.pages.push(this.current);
      return this.current;
    }

    space(n) {
      if (this.current.y - n < MARGIN) this.newPage();
      else this.current.y -= n;
    }

    text(str, { size = 10, bold = false, color = [0.1, 0.12, 0.2], indent = 0 } = {}) {
      const lineHeight = size + 4;
      if (this.current.y - lineHeight < MARGIN) this.newPage();
      const font = bold ? '/F2' : '/F1';
      this.current.ops.push(
        `BT ${font} ${size} Tf ${color[0]} ${color[1]} ${color[2]} rg ` +
        `1 0 0 1 ${MARGIN + indent} ${this.current.y - size} Tm (${escapeText(str)}) Tj ET`
      );
      this.current.y -= lineHeight;
    }

    rule() {
      if (this.current.y - 8 < MARGIN) this.newPage();
      this.current.ops.push(
        `0.78 0.80 0.86 RG 0.6 w ${MARGIN} ${this.current.y} m ${PAGE_W - MARGIN} ${this.current.y} l S`
      );
      this.current.y -= 10;
    }

    // rows: array of arrays; widths in points
    table(headers, rows, widths, size = 8.5) {
      const lineHeight = size + 5;
      const draw = (cells, bold) => {
        if (this.current.y - lineHeight < MARGIN) {
          this.newPage();
          draw(headers, true);
        }
        let x = MARGIN;
        cells.forEach((cell, i) => {
          const w = widths[i];
          const max = Math.max(1, Math.floor(w / (size * 0.55)));
          const txt = String(cell == null ? '' : cell).slice(0, max);
          const font = bold ? '/F2' : '/F1';
          const col = bold ? '0.35 0.38 0.48' : '0.10 0.12 0.20';
          this.current.ops.push(
            `BT ${font} ${size} Tf ${col} rg 1 0 0 1 ${x} ${this.current.y - size} Tm (${escapeText(txt)}) Tj ET`
          );
          x += w;
        });
        this.current.y -= lineHeight;
      };
      draw(headers, true);
      this.rule();
      rows.forEach((r) => draw(r, false));
    }

    // dataUrl must be image/jpeg
    image(dataUrl, drawW, drawH, pxW, pxH) {
      if (!dataUrl || !dataUrl.startsWith('data:image/jpeg;base64,')) return;
      const b64 = dataUrl.slice('data:image/jpeg;base64,'.length);
      const bin = atob(b64);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      const name = `/Im${this.images.length + 1}`;
      this.images.push({ name, bytes, pxW, pxH });
      if (this.current.y - drawH < MARGIN) this.newPage();
      const y = this.current.y - drawH;
      this.current.ops.push(`q ${drawW} 0 0 ${drawH} ${MARGIN} ${y} cm ${name} Do Q`);
      this.current.y = y - 12;
      this.current.usesImages = true;
    }

    build() {
      const enc = new TextEncoder();
      const chunks = [];
      const offsets = [];
      let length = 0;

      const push = (data) => {
        const bytes = typeof data === 'string' ? enc.encode(data) : data;
        chunks.push(bytes);
        length += bytes.length;
      };
      const obj = (num, body, streamBytes) => {
        offsets[num] = length;
        push(`${num} 0 obj\n`);
        push(body);
        if (streamBytes) {
          push('\nstream\n');
          push(streamBytes);
          push('\nendstream');
        }
        push('\nendobj\n');
      };

      const pageCount = this.pages.length;
      // 1 catalog, 2 pages, 3 font F1, 4 font F2, then per page: page + content
      const firstPageObj = 5;
      const imageObjStart = firstPageObj + pageCount * 2;

      push('%PDF-1.4\n%\xE2\xE3\xCF\xD3\n');

      const kids = [];
      for (let i = 0; i < pageCount; i++) kids.push(`${firstPageObj + i * 2} 0 R`);

      obj(1, `<< /Type /Catalog /Pages 2 0 R >>`);
      obj(2, `<< /Type /Pages /Count ${pageCount} /Kids [${kids.join(' ')}] >>`);
      obj(3, `<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>`);
      obj(4, `<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>`);

      const xobjEntries = this.images
        .map((img, i) => `${img.name} ${imageObjStart + i} 0 R`)
        .join(' ');

      this.pages.forEach((page, i) => {
        const pageNum = firstPageObj + i * 2;
        const contentNum = pageNum + 1;
        const resources =
          `<< /Font << /F1 3 0 R /F2 4 0 R >>` +
          (xobjEntries ? ` /XObject << ${xobjEntries} >>` : '') +
          ` >>`;
        obj(
          pageNum,
          `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${PAGE_W} ${PAGE_H}] ` +
          `/Resources ${resources} /Contents ${contentNum} 0 R >>`
        );
        const content = page.ops.join('\n');
        const contentBytes = enc.encode(content);
        obj(contentNum, `<< /Length ${contentBytes.length} >>`, contentBytes);
      });

      this.images.forEach((img, i) => {
        obj(
          imageObjStart + i,
          `<< /Type /XObject /Subtype /Image /Width ${img.pxW} /Height ${img.pxH} ` +
          `/ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length ${img.bytes.length} >>`,
          img.bytes
        );
      });

      const totalObjs = imageObjStart + this.images.length;
      const xrefStart = length;
      let xref = `xref\n0 ${totalObjs}\n0000000000 65535 f \n`;
      for (let n = 1; n < totalObjs; n++) {
        xref += String(offsets[n] || 0).padStart(10, '0') + ' 00000 n \n';
      }
      push(xref);
      push(
        `trailer\n<< /Size ${totalObjs} /Root 1 0 R /Info << /Title (${escapeText(this.title)}) ` +
        `/Producer (honeystack) >> >>\nstartxref\n${xrefStart}\n%%EOF\n`
      );

      const out = new Uint8Array(length);
      let at = 0;
      for (const c of chunks) { out.set(c, at); at += c.length; }
      return new Blob([out], { type: 'application/pdf' });
    }
  }

  window.PdfDoc = PdfDoc;
  window.PDF_PAGE = { W: PAGE_W, H: PAGE_H, MARGIN };
})();
