/* Render only real browser history. Filenames and result labels are text nodes. */
(function () {
    function renderOverview() {
        var history = [];
        try { var saved = JSON.parse(localStorage.getItem('malware_scan_history') || '[]'); if (Array.isArray(saved)) history = saved.filter(function (h) { return h && typeof h === 'object'; }); } catch (e) {}
        document.getElementById('homeScans').textContent = history.length;
        document.getElementById('homeSamples').textContent = history.reduce(function (sum, h) { var n = Number(h.total_samples); return sum + (Number.isFinite(n) && n >= 0 ? n : 1); }, 0).toLocaleString('vi-VN');
        document.getElementById('homeEmpty').hidden = history.length > 0;
        document.getElementById('homeRecentTable').hidden = history.length === 0;
        var body = document.getElementById('homeRecentBody');
        body.replaceChildren();
        history.slice(0, 4).forEach(function (item) {
            var row = document.createElement('tr');
            var file = document.createElement('td'); file.className = 'recent-filename';
            var icon = document.createElement('i'); icon.className = 'far fa-file-lines me-2 text-muted';
            file.append(icon, document.createTextNode(String(item.filename || 'Chưa có tên file')));
            var time = document.createElement('td'); time.className = 'small text-muted';
            var date = new Date(item.timestamp); time.textContent = Number.isNaN(date.getTime()) ? '—' : date.toLocaleDateString('vi-VN');
            var verdict = document.createElement('td'); verdict.className = 'text-end';
            var chip = document.createElement('span'); chip.className = 'chip';
            var first = item.first_sample || {}; chip.textContent = first.name || 'Chưa có kết quả';
            if (['Cao', 'Rất cao'].includes(first.risk_level)) chip.classList.add('chip--danger');
            else if (first.risk_level === 'Trung bình') chip.classList.add('chip--caution');
            verdict.appendChild(chip); row.append(file, time, verdict); body.appendChild(row);
        });
    }
    renderOverview();
    window.addEventListener('storage', renderOverview);
    window.addEventListener('malware-history-updated', renderOverview);
})();
